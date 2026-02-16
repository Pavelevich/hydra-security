import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";
import path from "node:path";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import os from "node:os";
import { runFullScan, runDiffScan } from "../orchestrator/run-scan.js";
import { toMarkdownReport } from "../output/report.js";
import { toSarif } from "../output/sarif.js";
import type { ScanResult } from "../types.js";

const PROJECT_ROOT = path.resolve(import.meta.dirname, "../..");

// --- GitHub URL resolution ---
const GITHUB_URL_RE = /^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/;

function isGitHubUrl(input: string): boolean {
  return GITHUB_URL_RE.test(input);
}

function repoSlugFromUrl(url: string): string {
  const match = url.match(GITHUB_URL_RE);
  if (!match) throw new Error(`Invalid GitHub URL: ${url}`);
  return `${match[1]}-${match[2]}`;
}

async function gitCloneDepthOne(url: string, destination: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("git", ["clone", "--depth", "1", url, destination], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("git clone timed out after 120000ms"));
    }, 120_000);
    let stderr = "";

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      if (code === 0) {
        resolve();
        return;
      }
      const detail = stderr.trim();
      reject(new Error(detail ? `git clone failed (${code}): ${detail}` : `git clone failed (${code})`));
    });
  });
}

async function resolveTarget(input: string): Promise<{ localPath: string; cleanup: (() => Promise<void>) | null; source: string }> {
  if (!isGitHubUrl(input)) {
    const resolved = path.isAbsolute(input) ? input : path.resolve(PROJECT_ROOT, input);
    return { localPath: resolved, cleanup: null, source: resolved };
  }

  const slug = repoSlugFromUrl(input);
  const tmpDir = path.join(os.tmpdir(), `hydra-scan-${slug}-${Date.now()}`);
  await fs.mkdir(tmpDir, { recursive: true });

  try {
    await gitCloneDepthOne(input, tmpDir);
  } catch (err) {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
    throw new Error(`Failed to clone ${input}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const cleanup = async () => {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
  };

  return { localPath: tmpDir, cleanup, source: input };
}

// --- Deep analysis helpers ---
const CONTEXT_LINES = 40;
const MAX_SOURCE_BYTES = 80_000; // Cap total source to avoid blowing context
const SOURCE_EXTENSIONS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".java", ".rb", ".php", ".cs", ".rs", ".swift", ".kt", ".scala", ".sh"];

async function listSourceFiles(dir: string): Promise<string[]> {
  const results: string[] = [];
  async function walk(d: string): Promise<void> {
    let entries;
    try { entries = await fs.readdir(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(d, entry.name);
      if (entry.isDirectory() && !entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name !== "target") {
        await walk(full);
      } else if (entry.isFile() && SOURCE_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
        results.push(full);
      }
    }
  }
  await walk(dir);
  return results.sort();
}

async function extractFindingContexts(findings: import("../types.js").Finding[]): Promise<string> {
  const seen = new Set<string>();
  const blocks: string[] = [];

  for (const f of findings) {
    const key = `${f.file}:${f.vuln_class}`;
    if (seen.has(key)) continue;
    seen.add(key);

    let source: string;
    try { source = await fs.readFile(f.file, "utf8"); } catch { continue; }

    const lines = source.split("\n");
    const start = Math.max(0, f.line - 1 - CONTEXT_LINES);
    const end = Math.min(lines.length, f.line - 1 + CONTEXT_LINES);
    const snippet = lines.slice(start, end).map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === f.line ? ">>>" : "   ";
      return `${marker} ${String(lineNum).padStart(4)} | ${l}`;
    }).join("\n");

    const relFile = f.file.split("/").slice(-3).join("/");
    blocks.push(
      `### Finding: ${f.title}\n` +
      `- Vulnerability: \`${f.vuln_class}\` | Severity: ${f.severity} | Confidence: ${f.confidence}%\n` +
      `- Location: \`${relFile}:${f.line}\`\n` +
      `- Scanner: \`${f.scanner_id}\`\n` +
      `- Description: ${f.description}\n` +
      `- Evidence: \`${f.evidence}\`\n\n` +
      `\`\`\`text\n${snippet}\n\`\`\``
    );
  }

  return blocks.join("\n\n---\n\n");
}

async function extractAllSources(rootPath: string): Promise<string> {
  const files = await listSourceFiles(rootPath);
  const blocks: string[] = [];
  let totalBytes = 0;

  for (const filePath of files) {
    if (totalBytes >= MAX_SOURCE_BYTES) {
      blocks.push(`\n... (truncated — ${files.length - blocks.length} more files, ${MAX_SOURCE_BYTES} byte limit reached)`);
      break;
    }

    let source: string;
    try { source = await fs.readFile(filePath, "utf8"); } catch { continue; }
    totalBytes += source.length;

    const relFile = filePath.replace(rootPath + "/", "");
    const numbered = source.split("\n").map((l, i) => `${String(i + 1).padStart(4)} | ${l}`).join("\n");
    blocks.push(`### \`${relFile}\` (${source.split("\n").length} lines)\n\n\`\`\`text\n${numbered}\n\`\`\``);
  }

  return blocks.join("\n\n---\n\n");
}

const DEEP_ANALYSIS_FINDINGS_PROMPT = `
## HYDRA DEEP ANALYSIS — Adversarial Validation

Pattern scanners detected the findings below. You must now validate each one.
For EACH finding, act as three agents:

### RED TEAM (Attacker)
- Can this be exploited? Write a concrete attack scenario.
- Estimate economic impact. Confidence (0-100).

### BLUE TEAM (Defender)
- What mitigations exist? Is the code path reachable?
- Environmental protections (runtime checks, authz, network controls, sandboxing)?
- Recommendation: CONFIRMED / MITIGATED / INFEASIBLE

### JUDGE (Verdict)
- Verdict: CONFIRMED / LIKELY / DISPUTED / FALSE_POSITIVE
- Final severity + confidence. One-paragraph reasoning.

### Output: for each finding produce:
| Role | Assessment |
|------|-----------|
| Red Team | ... |
| Blue Team | ... |
| Judge | **VERDICT** — ... |

Final summary table at the end.

---

`;

const DEEP_ANALYSIS_FULL_REVIEW_PROMPT = `
## HYDRA DEEP ANALYSIS — Full Security Review

Pattern scanners found 0 automated findings. This does NOT mean the code is safe.
You must now perform a comprehensive manual security audit of the source code below.

### Analyze for these vulnerability classes:

**Secrets & Credentials**
- Hardcoded secrets / API keys / tokens
- Insecure secret handling in config or source

**Injection**
- SQL injection via string-built queries
- Command injection via shell/process execution
- XSS via unsafe HTML sinks

**Deserialization & Parsing**
- Unsafe deserialization of untrusted data
- YAML/pickle/object deserialization abuse paths

**Auth & Access Control**
- Missing authentication/authorization checks
- Broken trust boundaries between components

**Business Logic**
- Privilege escalation paths
- Broken invariants, unsafe defaults, or abuseable workflows

### Output Format

For each vulnerability found, produce:

| Field | Value |
|-------|-------|
| Vulnerability | [class] |
| Severity | CRITICAL / HIGH / MEDIUM / LOW |
| Location | file:line |
| Description | ... |
| Attack Scenario | Step-by-step exploit |
| Confidence | 0-100% |

Then a final summary:
| # | Vulnerability | Severity | Location | Confidence |
|---|--------------|----------|----------|:----------:|

If the code is genuinely secure, explain WHY for each category above.

---

## Source Code

`;

function buildScanSummary(result: ScanResult): string {
  const parts: string[] = [];
  const agentRuns = result.agent_runs ?? [];
  const hasLlm = agentRuns.some((r) => r.agent_id.startsWith("llm.scanner"));
  const duration = new Date(result.completed_at).getTime() - new Date(result.started_at).getTime();

  // Findings count
  parts.push(`Found ${result.findings.length} finding(s) across ${agentRuns.length} scanner(s) in ${duration}ms.`);

  // Pipeline stages that ran
  const stages: string[] = [];
  stages.push("pattern-scanners");
  stages.push("deterministic-signals");
  if (hasLlm) stages.push("llm-scanners");
  if (result.adversarial_results?.length) stages.push("adversarial-validation");
  if (result.patch_results?.length) stages.push("patch-generation");
  parts.push(`Pipeline: [${stages.join(" -> ")}]`);

  // Stages that were skipped and why
  const skipped: string[] = [];
  if (!hasLlm) skipped.push("LLM scanners (no ANTHROPIC_API_KEY)");
  if (!result.adversarial_results?.length && result.findings.length > 0) {
    skipped.push("Adversarial validation (use deep=true for agent-side analysis, or adversarial=true + ANTHROPIC_API_KEY for server-side)");
  }
  if (!result.patch_results?.length) {
    skipped.push("Patch generation (set patch=true + adversarial=true)");
  }
  if (skipped.length > 0) {
    parts.push(`Skipped: ${skipped.join("; ")}`);
  }

  // Adversarial results
  if (result.adversarial_results?.length) {
    const confirmed = result.adversarial_results.filter((r) => r.judge?.verdict === "confirmed").length;
    const likely = result.adversarial_results.filter((r) => r.judge?.verdict === "likely").length;
    parts.push(`Adversarial: ${confirmed} confirmed, ${likely} likely out of ${result.adversarial_results.length} validated.`);
  }

  // Patch results
  if (result.patch_results?.length) {
    const approved = result.patch_results.filter((r) => r.status === "patched_and_verified").length;
    parts.push(`Patches: ${approved}/${result.patch_results.length} approved.`);
  }

  return parts.join("\n");
}

const server = new McpServer({
  name: "hydra-security",
  version: "0.1.0",
});

// --- Tool 1: hydra_scan ---
server.registerTool(
  "hydra_scan",
  {
    description:
      "Run a full Hydra security scan on a repository (general appsec by default, Solana profile when detected). " +
      "Accepts a local path OR a GitHub URL (e.g. https://github.com/org/repo). " +
      "Set deep=true for adversarial Red/Blue/Judge analysis — this returns source code context " +
      "with each finding so YOU (the calling agent) can perform the deep analysis directly. " +
      "No API key needed for deep mode. " +
      "Alternatively, set adversarial=true with ANTHROPIC_API_KEY for server-side LLM validation.",
    inputSchema: {
      target_path: z
        .string()
        .describe("Local path or GitHub URL (https://github.com/org/repo) of the repository to scan"),
      deep: z
        .boolean()
        .optional()
        .describe("Return findings with source code context for YOU to perform Red/Blue/Judge adversarial analysis (no API key needed)"),
      adversarial: z
        .boolean()
        .optional()
        .describe("Run server-side adversarial validation via Anthropic API (requires ANTHROPIC_API_KEY)"),
      patch: z
        .boolean()
        .optional()
        .describe("Generate and verify patches for confirmed findings"),
    },
  },
  async ({ target_path, deep, adversarial, patch }) => {
    let target;
    try {
      target = await resolveTarget(target_path);
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Target resolution failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }

    try {
      const result = await runFullScan(target.localPath, {
        adversarial: adversarial ?? false,
        patch: patch ?? false,
      });
      const report = toMarkdownReport(result);
      const summary = buildScanSummary(result);

      const content: Array<{ type: "text"; text: string }> = [];

      if (target.cleanup) {
        content.push({ type: "text" as const, text: `Cloned ${target.source} for scanning.` });
      }

      content.push({ type: "text" as const, text: summary });
      content.push({ type: "text" as const, text: report });

      // Deep mode: always provide source context for agent-side analysis
      if (deep) {
        if (result.findings.length > 0) {
          // Findings exist — validate them with Red/Blue/Judge
          const contexts = await extractFindingContexts(result.findings);
          content.push({ type: "text" as const, text: DEEP_ANALYSIS_FINDINGS_PROMPT + contexts });
        } else {
          // No findings — full manual security review of all source files
          const allSources = await extractAllSources(target.localPath);
          content.push({ type: "text" as const, text: DEEP_ANALYSIS_FULL_REVIEW_PROMPT + allSources });
        }
      }

      return { content };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Scan failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    } finally {
      if (target.cleanup) await target.cleanup();
    }
  }
);

// --- Tool 2: hydra_diff_scan ---
server.registerTool(
  "hydra_diff_scan",
  {
    description:
      "Run a differential Hydra security scan on only the files changed since a git reference. " +
      "Accepts a local path OR a GitHub URL. " +
      "Set adversarial=true to validate findings with the Red/Blue/Judge swarm.",
    inputSchema: {
      target_path: z
        .string()
        .describe("Local path or GitHub URL (https://github.com/org/repo) of the repository"),
      base_ref: z
        .string()
        .optional()
        .describe("Git base reference (e.g. 'origin/main', 'HEAD~3')"),
      head_ref: z
        .string()
        .optional()
        .describe("Git head reference (defaults to working directory)"),
      adversarial: z
        .boolean()
        .optional()
        .describe("Run adversarial Red/Blue/Judge validation on findings (requires ANTHROPIC_API_KEY)"),
      patch: z
        .boolean()
        .optional()
        .describe("Generate and verify patches for confirmed findings"),
    },
  },
  async ({ target_path, base_ref, head_ref, adversarial, patch }) => {
    let target;
    try {
      target = await resolveTarget(target_path);
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Target resolution failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }

    try {
      const result = await runDiffScan(target.localPath, {
        baseRef: base_ref,
        headRef: head_ref,
        adversarial: adversarial ?? false,
        patch: patch ?? false,
      });
      const report = toMarkdownReport(result);
      const summary = buildScanSummary(result);

      return {
        content: [
          ...(target.cleanup ? [{ type: "text" as const, text: `Cloned ${target.source} for scanning.` }] : []),
          { type: "text" as const, text: summary },
          { type: "text" as const, text: report },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Diff scan failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    } finally {
      if (target.cleanup) await target.cleanup();
    }
  }
);

// --- Tool 3: hydra_report_sarif ---
server.registerTool(
  "hydra_report_sarif",
  {
    description:
      "Convert a Hydra scan result JSON into SARIF 2.1.0 format for GitHub Security tab or IDE integration.",
    inputSchema: {
      scan_result_json: z
        .string()
        .describe("JSON string of a ScanResult object (from a previous hydra_scan call)"),
    },
  },
  async ({ scan_result_json }) => {
    try {
      const result = JSON.parse(scan_result_json) as ScanResult;
      const sarif = toSarif(result);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(sarif, null, 2) },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `SARIF conversion failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 4: hydra_eval ---
function runBunScript(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("bun", ["run", script], {
      cwd: PROJECT_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data: Buffer) => { stdout += data.toString(); });
    child.stderr.on("data", (data: Buffer) => { stderr += data.toString(); });
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout || stderr);
      } else {
        reject(new Error(`Script '${script}' exited with code ${code}:\n${stderr || stdout}`));
      }
    });
    child.on("error", reject);
  });
}

server.registerTool(
  "hydra_eval",
  {
    description:
      "Run the Hydra evaluation suite against benchmark datasets. Compares Hydra vs baselines and reports precision/recall metrics.",
    inputSchema: {
      dataset: z
        .enum(["d1", "d2", "d3", "d4", "core", "all"])
        .describe(
          "Dataset to evaluate: d1/d2 (seeded), d3 (clean controls), d4 (holdout), core (d1+d2), all (d1-d4)"
        ),
    },
  },
  async ({ dataset }) => {
    const scriptMap: Record<string, string> = {
      d1: "eval:d1",
      d2: "eval:d2",
      d3: "eval:d3",
      d4: "eval:d4",
      core: "eval:core",
      all: "eval:phase0",
    };

    const script = scriptMap[dataset];
    try {
      const output = await runBunScript(script);
      return {
        content: [{ type: "text" as const, text: output }],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 5: hydra_list_scanners ---
server.registerTool(
  "hydra_list_scanners",
  {
    description:
      "List all available Hydra security scanners and the vulnerability classes they detect.",
  },
  async () => {
    const hasApiKey = !!process.env.ANTHROPIC_API_KEY;
    const scanners = [
      {
        id: "scanner.generic.appsec",
        type: "pattern",
        active: true,
        vuln_classes: ["hardcoded_secret", "command_injection", "sql_injection", "xss", "insecure_deserialization"],
        description: "Generic application security scanner for common issues in web/backend codebases.",
      },
      {
        id: "scanner.solana.account-validation",
        type: "pattern",
        active: true,
        vuln_classes: ["missing_signer_check", "missing_has_one", "account_type_confusion"],
        description: "Detects missing signer checks, relationship constraints, and account type confusion via regex patterns with context-aware mitigation.",
      },
      {
        id: "scanner.solana.cpi",
        type: "pattern",
        active: true,
        vuln_classes: ["arbitrary_cpi", "cpi_signer_seed_bypass", "cpi_reentrancy"],
        description: "Detects unsafe cross-program invocation patterns including arbitrary CPI targets, reentrancy, and signer seed bypass.",
      },
      {
        id: "scanner.solana.pda",
        type: "pattern",
        active: true,
        vuln_classes: ["non_canonical_bump", "seed_collision", "attacker_controlled_seed"],
        description: "Detects PDA derivation issues including non-canonical bumps, missing seed domain separation, and attacker-controlled seeds.",
      },
      {
        id: "signal.deterministic.adapters",
        type: "deterministic",
        active: true,
        vuln_classes: ["missing_signer_check", "arbitrary_cpi", "non_canonical_bump"],
        description: "Rule-based deterministic signal detection (regex lint-level checks).",
      },
      {
        id: "llm.scanner.solana.account-validation",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["missing_signer_check", "missing_has_one", "account_type_confusion"],
        description: "LLM-powered deep analysis of account validation patterns. Requires ANTHROPIC_API_KEY.",
      },
      {
        id: "llm.scanner.generic.secrets",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["hardcoded_secret"],
        description: "LLM-powered deep analysis of credential leakage patterns. Requires ANTHROPIC_API_KEY.",
      },
      {
        id: "llm.scanner.generic.command-injection",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["command_injection"],
        description: "LLM-powered deep analysis of command execution risks. Requires ANTHROPIC_API_KEY.",
      },
      {
        id: "llm.scanner.generic.injection-and-deserialization",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["sql_injection", "xss", "insecure_deserialization"],
        description: "LLM-powered deep analysis of injection and deserialization risks. Requires ANTHROPIC_API_KEY.",
      },
      {
        id: "llm.scanner.solana.cpi",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["arbitrary_cpi", "cpi_signer_seed_bypass", "cpi_reentrancy"],
        description: "LLM-powered deep analysis of CPI patterns. Requires ANTHROPIC_API_KEY.",
      },
      {
        id: "llm.scanner.solana.pda",
        type: "llm",
        active: hasApiKey,
        vuln_classes: ["non_canonical_bump", "seed_collision", "attacker_controlled_seed"],
        description: "LLM-powered deep analysis of PDA derivation patterns. Requires ANTHROPIC_API_KEY.",
      },
    ];

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(scanners, null, 2),
        },
      ],
    };
  }
);

// --- Start server ---
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Hydra Security MCP server running on stdio");
}

main().catch((err) => {
  console.error("MCP server error:", err);
  process.exit(1);
});
