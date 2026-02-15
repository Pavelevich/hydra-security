import { execFile } from "node:child_process";

interface ExecOutput {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runGh(args: string[], input?: string, timeoutMs = 30_000): Promise<ExecOutput> {
  return new Promise((resolve) => {
    const child = execFile("gh", args, { timeout: timeoutMs, maxBuffer: 5 * 1024 * 1024 }, (error, stdout, stderr) => {
      const exitCode = error && "code" in error ? (error.code as number) ?? 1 : 0;
      resolve({ stdout: stdout ?? "", stderr: stderr ?? "", exitCode });
    });

    if (input && child.stdin) {
      child.stdin.write(input);
      child.stdin.end();
    }
  });
}

export async function createCheckRun(
  owner: string,
  repo: string,
  headSha: string,
  name: string
): Promise<number> {
  const body = JSON.stringify({
    name,
    head_sha: headSha,
    status: "in_progress",
    started_at: new Date().toISOString()
  });

  const result = await runGh([
    "api",
    "--method", "POST",
    `/repos/${owner}/${repo}/check-runs`,
    "--input", "-"
  ], body);

  if (result.exitCode !== 0) {
    throw new Error(`Failed to create check run: ${result.stderr}`);
  }

  const parsed = JSON.parse(result.stdout);
  return parsed.id as number;
}

export interface CheckRunOutput {
  title: string;
  summary: string;
  sarif?: object;
}

type CheckConclusion = "success" | "failure" | "neutral" | "cancelled" | "timed_out" | "action_required";

export async function completeCheckRun(
  owner: string,
  repo: string,
  checkRunId: number,
  conclusion: CheckConclusion,
  output: CheckRunOutput
): Promise<void> {
  const body = JSON.stringify({
    status: "completed",
    conclusion,
    completed_at: new Date().toISOString(),
    output: {
      title: output.title,
      summary: output.summary
    }
  });

  const result = await runGh([
    "api",
    "--method", "PATCH",
    `/repos/${owner}/${repo}/check-runs/${checkRunId}`,
    "--input", "-"
  ], body);

  if (result.exitCode !== 0) {
    throw new Error(`Failed to complete check run: ${result.stderr}`);
  }

  // Upload SARIF if provided
  if (output.sarif) {
    await uploadSarif(owner, repo, output.sarif);
  }
}

async function uploadSarif(owner: string, repo: string, sarif: object): Promise<void> {
  // GitHub Code Scanning API expects base64 + gzip, but for simplicity
  // we use the gh CLI's `sarif upload` if available, or the API endpoint.
  const sarifJson = JSON.stringify(sarif);
  const sarifBase64 = Buffer.from(sarifJson).toString("base64");

  // Get the current commit SHA
  const shaResult = await runGh(["api", `/repos/${owner}/${repo}/commits/HEAD`, "--jq", ".sha"]);
  const commitSha = shaResult.stdout.trim();
  if (!commitSha) return;

  const body = JSON.stringify({
    commit_sha: commitSha,
    ref: "refs/heads/main",
    sarif: sarifBase64,
    tool_name: "hydra-security"
  });

  await runGh([
    "api",
    "--method", "POST",
    `/repos/${owner}/${repo}/code-scanning/sarifs`,
    "--input", "-"
  ], body);
}

export async function listCheckRuns(
  owner: string,
  repo: string,
  ref: string
): Promise<{ id: number; name: string; status: string; conclusion: string | null }[]> {
  const result = await runGh([
    "api",
    `/repos/${owner}/${repo}/commits/${ref}/check-runs`,
    "--jq", ".check_runs[] | {id, name, status, conclusion}"
  ]);

  if (result.exitCode !== 0 || !result.stdout.trim()) {
    return [];
  }

  // gh --jq outputs one JSON object per line
  return result.stdout
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}
