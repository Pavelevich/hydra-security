import { promises as fs } from "node:fs";
import type { BlueTeamAssessment, Finding, RedTeamAssessment } from "../../types";
import { LlmClient } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget, truncateToTokenBudget } from "../../llm/token-budget";
import { parseJsonResponse } from "../../llm/parser";

interface BlueTeamContext {
  finding: Finding;
  redTeamAssessment: RedTeamAssessment;
  sourceCode?: string;
}

async function readSourceContext(finding: Finding): Promise<string> {
  try {
    return await fs.readFile(finding.file, "utf8");
  } catch {
    return `[Could not read file: ${finding.file}]`;
  }
}

function formatRedTeamAssessment(assessment: RedTeamAssessment): string {
  if (!assessment.exploitable) {
    return `Not exploitable. Reason: ${assessment.reason ?? "unknown"}`;
  }

  const parts: string[] = [];
  parts.push(`Exploitable: yes (confidence: ${assessment.confidence})`);
  if (assessment.attack_steps.length > 0) {
    parts.push(`Attack steps:\n${assessment.attack_steps.map((s, i) => `  ${i + 1}. ${s}`).join("\n")}`);
  }
  if (assessment.economic_impact) {
    parts.push(`Economic impact: ${assessment.economic_impact}`);
  }
  if (assessment.sandbox_executed) {
    parts.push(`Sandbox result: exit_code=${assessment.sandbox_exit_code ?? "?"}`);
  }
  return parts.join("\n");
}

export async function runBlueTeamAgent(context: BlueTeamContext): Promise<BlueTeamAssessment> {
  const route = routeModelWithFallbacks("blue-team");
  const budget = computeTokenBudget(route.primary, "blue-team");
  const client = new LlmClient({ fallbackModels: route.fallbacks });

  const sourceCode = context.sourceCode || (await readSourceContext(context.finding));
  const truncated = truncateToTokenBudget(sourceCode, budget.maxInputTokens - 1500);

  const rendered = renderPrompt("blue-team", {
    vuln_class: context.finding.vuln_class,
    severity: context.finding.severity,
    file_path: context.finding.file,
    line: String(context.finding.line),
    title: context.finding.title,
    exploit_assessment: formatRedTeamAssessment(context.redTeamAssessment),
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

  if (!parsed.data) {
    return {
      existing_mitigations: [],
      reachable: true,
      reachability_reasoning: `Failed to parse Blue Team response: ${parsed.error}`,
      env_protections: [],
      economically_feasible: true,
      overall_risk_reduction: 0,
      recommendation: "confirmed"
    };
  }

  const data = parsed.data;

  return {
    existing_mitigations: Array.isArray(data.existing_mitigations)
      ? (data.existing_mitigations as string[]).map(String)
      : [],
    reachable: data.reachable !== false,
    reachability_reasoning:
      typeof data.reachability_reasoning === "string" ? data.reachability_reasoning : "",
    env_protections: Array.isArray(data.env_protections)
      ? (data.env_protections as string[]).map(String)
      : [],
    economically_feasible: data.economically_feasible !== false,
    overall_risk_reduction:
      typeof data.overall_risk_reduction === "number"
        ? Math.max(0, Math.min(100, data.overall_risk_reduction))
        : 0,
    recommendation: isValidRecommendation(data.recommendation) ? data.recommendation : "confirmed"
  };
}

function isValidRecommendation(
  value: unknown
): value is "confirmed" | "mitigated" | "infeasible" {
  return value === "confirmed" || value === "mitigated" || value === "infeasible";
}
