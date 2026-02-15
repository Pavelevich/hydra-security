import { promises as fs } from "node:fs";
import type { Finding, RedTeamAssessment } from "../../types";
import { LlmClient } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget, truncateToTokenBudget } from "../../llm/token-budget";
import { parseJsonResponse } from "../../llm/parser";
import { createSandbox, isSandboxAvailable, isSandboxImageBuilt } from "../../sandbox/runner";

interface RedTeamContext {
  finding: Finding;
  sourceCode: string;
  programId?: string;
}

async function readSourceContext(finding: Finding): Promise<string> {
  try {
    const content = await fs.readFile(finding.file, "utf8");
    return content;
  } catch {
    return `[Could not read file: ${finding.file}]`;
  }
}

async function tryExploitInSandbox(exploitCode: string): Promise<{
  executed: boolean;
  exitCode?: number;
  stdout?: string;
}> {
  const dockerAvailable = await isSandboxAvailable();
  if (!dockerAvailable) {
    return { executed: false };
  }

  const imageReady = await isSandboxImageBuilt("generic");
  if (!imageReady) {
    return { executed: false };
  }

  const session = await createSandbox("generic", { timeoutMs: 30_000 });
  try {
    await session.writeFile("/workspace/exploit.ts", exploitCode);
    const result = await session.exec(["bun", "run", "/workspace/exploit.ts"], 25_000);
    return {
      executed: true,
      exitCode: result.exit_code,
      stdout: result.stdout.slice(0, 4096)
    };
  } finally {
    await session.destroy();
  }
}

export async function runRedTeamAgent(context: RedTeamContext): Promise<RedTeamAssessment> {
  const route = routeModelWithFallbacks("red-team");
  const budget = computeTokenBudget(route.primary, "red-team");
  const client = new LlmClient({ fallbackModels: route.fallbacks });

  const sourceCode = context.sourceCode || (await readSourceContext(context.finding));
  const truncated = truncateToTokenBudget(sourceCode, budget.maxInputTokens - 1000);

  const rendered = renderPrompt("red-team", {
    vuln_class: context.finding.vuln_class,
    severity: context.finding.severity,
    file_path: context.finding.file,
    line: String(context.finding.line),
    title: context.finding.title,
    description: context.finding.description,
    code: truncated.text,
    program_id: context.programId ?? "unknown"
  });

  const response = await client.createMessage({
    model: route.primary,
    system: rendered.system,
    messages: [{ role: "user", content: rendered.user }],
    max_tokens: budget.maxOutputTokens,
    temperature: 0.3
  });

  const parsed = parseJsonResponse<Record<string, unknown>>(response.content);

  if (!parsed.data) {
    return {
      exploitable: false,
      attack_steps: [],
      confidence: 0,
      reason: `Failed to parse Red Team response: ${parsed.error}`,
      sandbox_executed: false
    };
  }

  const data = parsed.data;
  const exploitable = data.exploitable !== false;
  const exploitCode = typeof data.exploit_code === "string" ? data.exploit_code : undefined;
  const attackSteps = Array.isArray(data.attack_steps)
    ? (data.attack_steps as string[]).map(String)
    : [];
  const economicImpact = typeof data.economic_impact === "string" ? data.economic_impact : undefined;
  const confidence = typeof data.confidence === "number" ? data.confidence : 50;
  const reason = typeof data.reason === "string" ? data.reason : undefined;

  let sandboxExecuted = false;
  let sandboxExitCode: number | undefined;
  let sandboxStdout: string | undefined;

  if (exploitable && exploitCode) {
    try {
      const sandbox = await tryExploitInSandbox(exploitCode);
      sandboxExecuted = sandbox.executed;
      sandboxExitCode = sandbox.exitCode;
      sandboxStdout = sandbox.stdout;
    } catch {
      // Sandbox execution failed — not fatal
    }
  }

  return {
    exploitable,
    exploit_code: exploitCode,
    attack_steps: attackSteps,
    economic_impact: economicImpact,
    confidence,
    reason,
    sandbox_executed: sandboxExecuted,
    sandbox_exit_code: sandboxExitCode,
    sandbox_stdout: sandboxStdout
  };
}
