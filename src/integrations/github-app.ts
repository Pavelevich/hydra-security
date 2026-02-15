import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { runDiffScan, runFullScan } from "../orchestrator/run-scan";
import { postPrReview } from "./github-comments";
import { createCheckRun, completeCheckRun } from "./github-checks";
import { toSarif } from "../output/sarif";
import type { ScanResult } from "../types";

export interface GitHubAppConfig {
  webhookSecret: string;
  appId: string;
  privateKey: string;
  host?: string;
  port?: number;
}

interface WebhookEvent {
  action: string;
  installation?: { id: number };
  repository?: {
    full_name: string;
    clone_url: string;
    default_branch: string;
  };
  pull_request?: {
    number: number;
    head: { sha: string; ref: string };
    base: { sha: string; ref: string };
  };
  after?: string;
  before?: string;
  ref?: string;
  commits?: { added: string[]; removed: string[]; modified: string[] }[];
}

function verifySignature(payload: string, signature: string, secret: string): boolean {
  if (!signature.startsWith("sha256=")) return false;
  const expected = createHmac("sha256", secret).update(payload).digest("hex");
  const actual = signature.slice("sha256=".length);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(actual, "hex"));
}

function collectChangedFiles(event: WebhookEvent): string[] {
  const files = new Set<string>();
  if (event.commits) {
    for (const commit of event.commits) {
      for (const f of commit.added) files.add(f);
      for (const f of commit.modified) files.add(f);
    }
  }
  return [...files];
}

async function handlePullRequestEvent(event: WebhookEvent, repoPath: string): Promise<void> {
  const pr = event.pull_request;
  const repo = event.repository;
  if (!pr || !repo) return;

  if (event.action !== "opened" && event.action !== "synchronize") return;

  const [owner, repoName] = repo.full_name.split("/");

  // Create a check run (in_progress)
  let checkRunId: number | undefined;
  try {
    checkRunId = await createCheckRun(owner, repoName, pr.head.sha, "Hydra Security Audit");
  } catch {
    // Check API may not be available — continue without it
  }

  let result: ScanResult;
  try {
    result = await runDiffScan(repoPath, {
      baseRef: pr.base.ref,
      headRef: pr.head.ref
    });
  } catch (error) {
    if (checkRunId !== undefined) {
      await completeCheckRun(owner, repoName, checkRunId, "failure", {
        title: "Hydra Security Audit",
        summary: `Scan failed: ${error instanceof Error ? error.message : "unknown error"}`
      }).catch(() => {});
    }
    return;
  }

  // Post review comments
  try {
    await postPrReview(owner, repoName, pr.number, pr.head.sha, result);
  } catch {
    // Comment posting may fail if permissions are insufficient
  }

  // Complete the check run
  if (checkRunId !== undefined) {
    const hasCritical = result.findings.some((f) => f.severity === "CRITICAL");
    const hasHigh = result.findings.some((f) => f.severity === "HIGH");
    const conclusion = hasCritical || hasHigh ? "failure" : result.findings.length > 0 ? "neutral" : "success";

    const sarifOutput = toSarif(result);
    await completeCheckRun(owner, repoName, checkRunId, conclusion, {
      title: `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} detected`,
      summary: buildCheckSummary(result),
      sarif: sarifOutput
    }).catch(() => {});
  }
}

async function handlePushEvent(event: WebhookEvent, repoPath: string): Promise<void> {
  const repo = event.repository;
  if (!repo || !event.after) return;

  // Only scan pushes to the default branch
  const refBranch = event.ref?.replace("refs/heads/", "");
  if (refBranch !== repo.default_branch) return;

  const changedFiles = collectChangedFiles(event);
  if (changedFiles.length === 0) return;

  const [owner, repoName] = repo.full_name.split("/");

  let checkRunId: number | undefined;
  try {
    checkRunId = await createCheckRun(owner, repoName, event.after, "Hydra Security Audit");
  } catch {
    // Continue without check
  }

  let result: ScanResult;
  try {
    result = await runDiffScan(repoPath, {
      baseRef: event.before,
      headRef: event.after,
      changedFiles
    });
  } catch (error) {
    if (checkRunId !== undefined) {
      await completeCheckRun(owner, repoName, checkRunId, "failure", {
        title: "Hydra Security Audit",
        summary: `Scan failed: ${error instanceof Error ? error.message : "unknown error"}`
      }).catch(() => {});
    }
    return;
  }

  if (checkRunId !== undefined) {
    const hasCritical = result.findings.some((f) => f.severity === "CRITICAL");
    const hasHigh = result.findings.some((f) => f.severity === "HIGH");
    const conclusion = hasCritical || hasHigh ? "failure" : result.findings.length > 0 ? "neutral" : "success";

    await completeCheckRun(owner, repoName, checkRunId, conclusion, {
      title: `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} detected`,
      summary: buildCheckSummary(result)
    }).catch(() => {});
  }
}

function buildCheckSummary(result: ScanResult): string {
  const lines: string[] = [];
  const critical = result.findings.filter((f) => f.severity === "CRITICAL").length;
  const high = result.findings.filter((f) => f.severity === "HIGH").length;
  const medium = result.findings.filter((f) => f.severity === "MEDIUM").length;
  const low = result.findings.filter((f) => f.severity === "LOW").length;

  lines.push(`**${result.findings.length}** finding${result.findings.length === 1 ? "" : "s"} detected`);
  lines.push("");
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  if (critical > 0) lines.push(`| CRITICAL | ${critical} |`);
  if (high > 0) lines.push(`| HIGH | ${high} |`);
  if (medium > 0) lines.push(`| MEDIUM | ${medium} |`);
  if (low > 0) lines.push(`| LOW | ${low} |`);

  return lines.join("\n");
}

function writeJson(res: ServerResponse, body: unknown, status = 200): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  const MAX_BODY = 5 * 1024 * 1024;

  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BODY) throw new Error("payload_too_large");
    chunks.push(buf);
  }

  return Buffer.concat(chunks).toString("utf8");
}

export interface RepoPathResolver {
  (repoFullName: string): Promise<string>;
}

export function startGitHubApp(config: GitHubAppConfig, resolveRepoPath: RepoPathResolver): void {
  const host = config.host ?? "127.0.0.1";
  const port = config.port ?? 3000;

  const server = createServer(async (req, res) => {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://${host}:${port}`);

    if (method === "GET" && url.pathname === "/healthz") {
      writeJson(res, { status: "ok" });
      return;
    }

    if (method !== "POST" || url.pathname !== "/webhook") {
      writeJson(res, { error: "not_found" }, 404);
      return;
    }

    let body: string;
    try {
      body = await readBody(req);
    } catch {
      writeJson(res, { error: "payload_too_large" }, 413);
      return;
    }

    const signature = req.headers["x-hub-signature-256"] as string | undefined;
    if (!signature || !verifySignature(body, signature, config.webhookSecret)) {
      writeJson(res, { error: "invalid_signature" }, 401);
      return;
    }

    const eventType = req.headers["x-github-event"] as string | undefined;
    if (!eventType) {
      writeJson(res, { error: "missing_event_type" }, 400);
      return;
    }

    let event: WebhookEvent;
    try {
      event = JSON.parse(body) as WebhookEvent;
    } catch {
      writeJson(res, { error: "invalid_json" }, 400);
      return;
    }

    // Acknowledge immediately — process async
    writeJson(res, { received: true }, 200);

    const repoFullName = event.repository?.full_name;
    if (!repoFullName) return;

    let repoPath: string;
    try {
      repoPath = await resolveRepoPath(repoFullName);
    } catch {
      return;
    }

    try {
      if (eventType === "pull_request") {
        await handlePullRequestEvent(event, repoPath);
      } else if (eventType === "push") {
        await handlePushEvent(event, repoPath);
      }
    } catch (error) {
      console.error(`[github-app] Error handling ${eventType}:`, error);
    }
  });

  server.listen(port, host, () => {
    console.log(`Hydra GitHub App webhook listener on http://${host}:${port}/webhook`);
  });
}
