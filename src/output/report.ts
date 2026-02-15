import path from "node:path";
import type { ScanResult } from "../types";

export function toMarkdownReport(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("# Hydra Security Scan Report");
  lines.push("");
  lines.push(`- Target: \`${result.target.root_path}\``);
  lines.push(`- Mode: \`${result.target.mode}\``);
  lines.push(`- Started: ${result.started_at}`);
  lines.push(`- Completed: ${result.completed_at}`);
  lines.push(`- Findings: **${result.findings.length}**`);
  if (result.agent_runs && result.agent_runs.length > 0) {
    const completedAgents = result.agent_runs.filter((run) => run.status === "completed").length;
    const failedAgents = result.agent_runs.filter((run) => run.status === "failed").length;
    const timedOutAgents = result.agent_runs.filter((run) => run.status === "timed_out").length;
    lines.push(
      `- Agent Runs: ${result.agent_runs.length} total (${completedAgents} completed, ${failedAgents} failed, ${timedOutAgents} timed out)`
    );
  }
  if (result.threat_model) {
    const status = result.threat_model.loaded_from_cache ? "cache-hit" : "generated";
    lines.push(
      `- Threat Model: \`${result.threat_model.version.id}\` (rev ${result.threat_model.version.revision}, ${status})`
    );
  }
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings detected.");
    return lines.join("\n");
  }

  lines.push("| Severity | Class | File | Line | Confidence |");
  lines.push("|----------|-------|------|------|------------|");
  for (const finding of result.findings) {
    lines.push(
      `| ${finding.severity} | ${finding.vuln_class} | ${path.basename(finding.file)} | ${finding.line} | ${finding.confidence} |`
    );
  }
  lines.push("");
  lines.push("## Finding Details");
  lines.push("");
  for (const finding of result.findings) {
    lines.push(`### ${finding.title}`);
    lines.push(`- ID: \`${finding.id}\``);
    lines.push(`- Scanner: \`${finding.scanner_id}\``);
    lines.push(`- File: \`${finding.file}:${finding.line}\``);
    lines.push(`- Description: ${finding.description}`);
    lines.push(`- Evidence: \`${finding.evidence}\``);
    lines.push("");
  }

  return lines.join("\n");
}
