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
