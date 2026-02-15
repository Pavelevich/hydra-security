import type {
  BlueTeamAssessment,
  Finding,
  JudgeVerdict,
  RedTeamAssessment,
  Severity
} from "../../types";
import { LlmClient } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget } from "../../llm/token-budget";
import { parseJsonResponse } from "../../llm/parser";

interface JudgeContext {
  finding: Finding;
  redTeamAssessment: RedTeamAssessment;
  blueTeamAssessment: BlueTeamAssessment;
}

function formatRedTeam(assessment: RedTeamAssessment): string {
  const parts: string[] = [];
  parts.push(`Exploitable: ${assessment.exploitable}`);
  parts.push(`Confidence: ${assessment.confidence}`);
  if (assessment.attack_steps.length > 0) {
    parts.push(`Attack steps: ${assessment.attack_steps.join("; ")}`);
  }
  if (assessment.economic_impact) {
    parts.push(`Economic impact: ${assessment.economic_impact}`);
  }
  if (assessment.sandbox_executed) {
    parts.push(`Sandbox executed: exit_code=${assessment.sandbox_exit_code ?? "?"}`);
    if (assessment.sandbox_stdout) {
      parts.push(`Sandbox output: ${assessment.sandbox_stdout.slice(0, 500)}`);
    }
  } else {
    parts.push("Sandbox: not executed");
  }
  if (assessment.reason) {
    parts.push(`Reason: ${assessment.reason}`);
  }
  return parts.join("\n");
}

function formatBlueTeam(assessment: BlueTeamAssessment): string {
  const parts: string[] = [];
  parts.push(`Recommendation: ${assessment.recommendation}`);
  parts.push(`Reachable: ${assessment.reachable}`);
  parts.push(`Reachability reasoning: ${assessment.reachability_reasoning}`);
  parts.push(`Economically feasible: ${assessment.economically_feasible}`);
  parts.push(`Risk reduction: ${assessment.overall_risk_reduction}%`);
  if (assessment.existing_mitigations.length > 0) {
    parts.push(`Existing mitigations: ${assessment.existing_mitigations.join("; ")}`);
  }
  if (assessment.env_protections.length > 0) {
    parts.push(`Environment protections: ${assessment.env_protections.join("; ")}`);
  }
  return parts.join("\n");
}

const VALID_VERDICTS = new Set(["confirmed", "likely", "disputed", "false_positive"]);
const VALID_SEVERITIES = new Set<Severity>(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);

export async function runJudgeAgent(context: JudgeContext): Promise<JudgeVerdict> {
  const route = routeModelWithFallbacks("judge");
  const budget = computeTokenBudget(route.primary, "judge");
  const client = new LlmClient({ fallbackModels: route.fallbacks });

  const rendered = renderPrompt("judge", {
    vuln_class: context.finding.vuln_class,
    severity: context.finding.severity,
    confidence: String(context.finding.confidence),
    file_path: context.finding.file,
    line: String(context.finding.line),
    title: context.finding.title,
    scanner_evidence: context.finding.evidence,
    red_team_assessment: formatRedTeam(context.redTeamAssessment),
    blue_team_assessment: formatBlueTeam(context.blueTeamAssessment)
  });

  const response = await client.createMessage({
    model: route.primary,
    system: rendered.system,
    messages: [{ role: "user", content: rendered.user }],
    max_tokens: budget.maxOutputTokens,
    temperature: 0.1
  });

  const parsed = parseJsonResponse<Record<string, unknown>>(response.content);

  if (!parsed.data) {
    return fallbackVerdict(context, `Failed to parse Judge response: ${parsed.error}`);
  }

  const data = parsed.data;
  const verdict = VALID_VERDICTS.has(data.verdict as string)
    ? (data.verdict as JudgeVerdict["verdict"])
    : inferVerdict(context);
  const finalSeverity = VALID_SEVERITIES.has(data.final_severity as Severity)
    ? (data.final_severity as Severity)
    : context.finding.severity;
  const finalConfidence =
    typeof data.final_confidence === "number"
      ? Math.max(0, Math.min(100, Math.round(data.final_confidence)))
      : context.finding.confidence;

  return {
    verdict,
    final_severity: finalSeverity,
    final_confidence: finalConfidence,
    reasoning: typeof data.reasoning === "string" ? data.reasoning : "",
    evidence_summary: typeof data.evidence_summary === "string" ? data.evidence_summary : ""
  };
}

function inferVerdict(context: JudgeContext): JudgeVerdict["verdict"] {
  if (context.redTeamAssessment.sandbox_executed && context.redTeamAssessment.sandbox_exit_code === 0) {
    return "confirmed";
  }
  if (context.redTeamAssessment.exploitable && context.redTeamAssessment.confidence >= 70) {
    return "likely";
  }
  if (context.blueTeamAssessment.recommendation === "mitigated") {
    return "disputed";
  }
  if (context.blueTeamAssessment.recommendation === "infeasible") {
    return "false_positive";
  }
  return "likely";
}

function fallbackVerdict(context: JudgeContext, reason: string): JudgeVerdict {
  return {
    verdict: inferVerdict(context),
    final_severity: context.finding.severity,
    final_confidence: context.finding.confidence,
    reasoning: reason,
    evidence_summary: "Fallback verdict due to LLM parse failure"
  };
}
