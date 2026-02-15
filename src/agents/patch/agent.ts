import { promises as fs } from "node:fs";
import type { AdversarialResult, PatchProposal } from "../../types";
import { LlmClient } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget, truncateToTokenBudget } from "../../llm/token-budget";
import { parseJsonResponse } from "../../llm/parser";

async function readSource(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

function buildRootCause(result: AdversarialResult): string {
  const parts: string[] = [];

  if (result.red_team?.exploitable) {
    parts.push(`Red Team confirmed exploitable (confidence ${result.red_team.confidence}).`);
    if (result.red_team.attack_steps.length > 0) {
      parts.push(`Attack: ${result.red_team.attack_steps.join(" → ")}`);
    }
    if (result.red_team.economic_impact) {
      parts.push(`Impact: ${result.red_team.economic_impact}`);
    }
  }

  if (result.judge) {
    parts.push(`Judge verdict: ${result.judge.verdict} (${result.judge.final_severity}, confidence ${result.judge.final_confidence}).`);
    if (result.judge.reasoning) {
      parts.push(`Reasoning: ${result.judge.reasoning}`);
    }
  }

  if (parts.length === 0) {
    parts.push(`Scanner finding: ${result.finding.description}`);
  }

  return parts.join("\n");
}

export async function runPatchAgent(result: AdversarialResult): Promise<PatchProposal | undefined> {
  const verdict = result.judge?.verdict;
  if (verdict !== "confirmed" && verdict !== "likely") {
    return undefined;
  }

  const route = routeModelWithFallbacks("patch");
  const budget = computeTokenBudget(route.primary, "patch");
  const client = new LlmClient({ fallbackModels: route.fallbacks });

  const sourceCode = await readSource(result.finding.file);
  if (!sourceCode) return undefined;

  const truncated = truncateToTokenBudget(sourceCode, budget.maxInputTokens - 1500);
  const rootCause = buildRootCause(result);

  const rendered = renderPrompt("patch", {
    vuln_class: result.finding.vuln_class,
    severity: result.judge?.final_severity ?? result.finding.severity,
    file_path: result.finding.file,
    line: String(result.finding.line),
    title: result.finding.title,
    root_cause: rootCause,
    code: truncated.text
  });

  const response = await client.createMessage({
    model: route.primary,
    system: rendered.system,
    messages: [{ role: "user", content: rendered.user }],
    max_tokens: budget.maxOutputTokens,
    temperature: 0.2
  });

  const parsed = parseJsonResponse<Record<string, unknown>>(response.content);
  if (!parsed.data) return undefined;

  const data = parsed.data;

  return {
    finding_id: result.finding.id,
    file: result.finding.file,
    patch_diff: typeof data.patch_diff === "string" ? data.patch_diff : "",
    explanation: typeof data.explanation === "string" ? data.explanation : "",
    root_cause: rootCause,
    test_code: typeof data.test_code === "string" ? data.test_code : "",
    breaking_changes: Array.isArray(data.breaking_changes)
      ? (data.breaking_changes as string[]).map(String)
      : []
  };
}
