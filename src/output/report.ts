import path from "node:path";
import type { ScanResult, Finding, AdversarialResult, PatchResult, Severity } from "../types";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

const SEVERITY_ICON: Record<Severity, string> = {
  CRITICAL: "CRITICAL",
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
};

function durationStr(startedAt: string, completedAt: string): string {
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}min`;
}

function groupBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
  const map = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const arr = map.get(k) ?? [];
    arr.push(item);
    map.set(k, arr);
  }
  return map;
}

function severityDistribution(findings: Finding[]): Record<Severity, number> {
  const dist: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) dist[f.severity]++;
  return dist;
}

function pipelineStages(result: ScanResult): string[] {
  const lines: string[] = [];
  const hasApiKey = (result.agent_runs ?? []).some((r) => r.agent_id.startsWith("llm.scanner"));
  const patternAgents = (result.agent_runs ?? []).filter(
    (r) => !r.agent_id.startsWith("llm.scanner") && r.agent_id !== "signal.deterministic.adapters"
  );
  const deterministicAgents = (result.agent_runs ?? []).filter(
    (r) => r.agent_id === "signal.deterministic.adapters"
  );
  const llmAgents = (result.agent_runs ?? []).filter((r) => r.agent_id.startsWith("llm.scanner"));

  lines.push("| Stage | Status | Agents | Details |");
  lines.push("|-------|--------|--------|---------|");

  // Pattern scanners
  const patternCompleted = patternAgents.filter((r) => r.status === "completed").length;
  const patternTotal = patternAgents.length;
  lines.push(
    `| Pattern Scanners | ${patternCompleted === patternTotal ? "RAN" : "PARTIAL"} | ${patternCompleted}/${patternTotal} completed | Regex-based detection with context-aware mitigations |`
  );

  // Deterministic signals
  const detStatus = deterministicAgents.length > 0
    ? deterministicAgents[0].status === "completed" ? "RAN" : "FAILED"
    : "SKIPPED";
  lines.push(
    `| Deterministic Signals | ${detStatus} | ${deterministicAgents.length > 0 ? "1/1 completed" : "0/0"} | Rule-based lint-level checks |`
  );

  // LLM scanners
  if (hasApiKey) {
    const llmCompleted = llmAgents.filter((r) => r.status === "completed").length;
    const llmFailed = llmAgents.filter((r) => r.status === "failed" || r.status === "timed_out").length;
    lines.push(
      `| LLM Scanners | ${llmCompleted > 0 ? "RAN" : "FAILED"} | ${llmCompleted}/${llmAgents.length} completed${llmFailed > 0 ? `, ${llmFailed} failed` : ""} | Deep semantic analysis via Claude |`
    );
  } else {
    lines.push(
      `| LLM Scanners | SKIPPED | 0/3 | Requires ANTHROPIC_API_KEY environment variable |`
    );
  }

  // Adversarial pipeline
  if (result.adversarial_results && result.adversarial_results.length > 0) {
    const confirmed = result.adversarial_results.filter((r) => r.judge?.verdict === "confirmed").length;
    const likely = result.adversarial_results.filter((r) => r.judge?.verdict === "likely").length;
    lines.push(
      `| Adversarial Validation | RAN | Red/Blue/Judge x${result.adversarial_results.length} | ${confirmed} confirmed, ${likely} likely, ${result.adversarial_results.length - confirmed - likely} disputed/FP |`
    );
  } else if (result.findings.length > 0) {
    lines.push(
      `| Adversarial Validation | SKIPPED | 0 | Pass adversarial=true and set ANTHROPIC_API_KEY to enable |`
    );
  } else {
    lines.push(
      `| Adversarial Validation | N/A | 0 | No findings to validate |`
    );
  }

  // Patch pipeline
  if (result.patch_results && result.patch_results.length > 0) {
    const approved = result.patch_results.filter((r) => r.status === "patched_and_verified").length;
    lines.push(
      `| Patch Generation | RAN | ${result.patch_results.length} patches | ${approved} approved, ${result.patch_results.length - approved} rejected/pending |`
    );
  } else {
    lines.push(
      `| Patch Generation | SKIPPED | 0 | Pass patch=true with adversarial=true to enable |`
    );
  }

  return lines;
}

function formatFindingRow(f: Finding, idx: number): string {
  const relFile = f.file.includes("/") ? f.file.split("/").slice(-2).join("/") : f.file;
  return `| ${idx} | ${SEVERITY_ICON[f.severity]} | \`${f.vuln_class}\` | \`${relFile}:${f.line}\` | ${f.confidence}% | ${f.title} |`;
}

export function toMarkdownReport(result: ScanResult): string {
  const lines: string[] = [];
  const duration = durationStr(result.started_at, result.completed_at);
  const dist = severityDistribution(result.findings);
  const repoName = path.basename(result.target.root_path);

  // ── Header ──
  lines.push("# HYDRA SECURITY SCAN REPORT");
  lines.push("");

  // ── Scan Metadata ──
  lines.push("## Scan Metadata");
  lines.push("");
  lines.push("| Field | Value |");
  lines.push("|-------|-------|");
  lines.push(`| Target | \`${result.target.root_path}\` |`);
  lines.push(`| Repository | \`${repoName}\` |`);
  lines.push(`| Mode | ${result.target.mode === "diff" ? `Differential (${result.target.diff?.changed_files?.length ?? 0} files)` : "Full Scan"} |`);
  lines.push(`| Started | ${result.started_at} |`);
  lines.push(`| Duration | ${duration} |`);
  if (result.threat_model) {
    const status = result.threat_model.loaded_from_cache ? "cached" : "generated";
    lines.push(`| Threat Model | \`${result.threat_model.version.id}\` (rev ${result.threat_model.version.revision}, ${status}) |`);
  }
  lines.push(`| Total Findings | **${result.findings.length}** |`);
  lines.push("");

  // ── Severity Distribution ──
  lines.push("## Severity Distribution");
  lines.push("");
  lines.push("| CRITICAL | HIGH | MEDIUM | LOW |");
  lines.push("|----------|------|--------|-----|");
  lines.push(`| ${dist.CRITICAL} | ${dist.HIGH} | ${dist.MEDIUM} | ${dist.LOW} |`);
  lines.push("");

  // ── Pipeline Status ──
  lines.push("## Pipeline Execution");
  lines.push("");
  lines.push(...pipelineStages(result));
  lines.push("");

  // ── Agent Run Details ──
  if (result.agent_runs && result.agent_runs.length > 0) {
    lines.push("## Scanner Performance");
    lines.push("");
    lines.push("| Scanner | Status | Duration | Findings |");
    lines.push("|---------|--------|----------|----------|");
    for (const run of result.agent_runs) {
      const statusLabel = run.status === "completed" ? "OK"
        : run.status === "timed_out" ? "TIMEOUT"
        : run.status === "failed" ? "FAIL"
        : run.status;
      const dur = run.duration_ms != null ? `${run.duration_ms}ms` : "-";
      const count = run.finding_count != null ? String(run.finding_count) : "-";
      lines.push(`| \`${run.agent_id}\` | ${statusLabel} | ${dur} | ${count} |`);
    }
    lines.push("");
  }

  // ── No Findings ──
  if (result.findings.length === 0) {
    lines.push("## Results");
    lines.push("");
    lines.push("No security findings detected.");
    lines.push("");
    return lines.join("\n");
  }

  // ── Findings Summary Table ──
  lines.push("## Findings Summary");
  lines.push("");
  lines.push("| # | Severity | Vulnerability Class | Location | Confidence | Title |");
  lines.push("|---|----------|--------------------:|----------|:----------:|-------|");

  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.confidence - a.confidence
  );
  for (let i = 0; i < sorted.length; i++) {
    lines.push(formatFindingRow(sorted[i], i + 1));
  }
  lines.push("");

  // ── Findings Grouped by Vulnerability Class ──
  lines.push("## Findings by Vulnerability Class");
  lines.push("");

  const byClass = groupBy(sorted, (f) => f.vuln_class);
  for (const [vulnClass, findings] of byClass) {
    lines.push(`### ${vulnClass} (${findings.length} finding${findings.length > 1 ? "s" : ""})`);
    lines.push("");
    for (const f of findings) {
      const relFile = f.file.includes("/") ? f.file.split("/").slice(-2).join("/") : f.file;
      lines.push(`**${f.title}**`);
      lines.push(`- Location: \`${relFile}:${f.line}\``);
      lines.push(`- Severity: ${f.severity} | Confidence: ${f.confidence}% | Scanner: \`${f.scanner_id}\``);
      lines.push(`- ${f.description}`);
      lines.push(`- Evidence: \`${f.evidence}\``);
      lines.push("");
    }
  }

  // ── Adversarial Results ──
  if (result.adversarial_results && result.adversarial_results.length > 0) {
    lines.push("## Adversarial Validation Results");
    lines.push("");
    lines.push("| # | Finding | Verdict | Red Team | Blue Team | Final Severity | Final Confidence |");
    lines.push("|---|---------|---------|----------|-----------|----------------|:----------------:|");

    for (let i = 0; i < result.adversarial_results.length; i++) {
      const ar = result.adversarial_results[i];
      const verdict = ar.judge?.verdict ?? "pending";
      const redExploitable = ar.red_team?.exploitable ? "Exploitable" : "Not exploitable";
      const blueRec = ar.blue_team?.recommendation ?? "-";
      const finalSev = ar.judge?.final_severity ?? "-";
      const finalConf = ar.judge?.final_confidence != null ? `${ar.judge.final_confidence}%` : "-";
      lines.push(
        `| ${i + 1} | ${ar.finding.title} | **${verdict.toUpperCase()}** | ${redExploitable} | ${blueRec} | ${finalSev} | ${finalConf} |`
      );
    }
    lines.push("");

    // Detailed adversarial reasoning
    const confirmed = result.adversarial_results.filter(
      (r) => r.judge?.verdict === "confirmed" || r.judge?.verdict === "likely"
    );
    if (confirmed.length > 0) {
      lines.push("### Confirmed / Likely Findings");
      lines.push("");
      for (const ar of confirmed) {
        lines.push(`**${ar.finding.title}** (${ar.judge!.verdict})`);
        lines.push(`- Judge reasoning: ${ar.judge!.reasoning}`);
        if (ar.red_team?.attack_steps?.length) {
          lines.push(`- Attack steps: ${ar.red_team.attack_steps.join(" -> ")}`);
        }
        if (ar.red_team?.economic_impact) {
          lines.push(`- Economic impact: ${ar.red_team.economic_impact}`);
        }
        lines.push("");
      }
    }
  }

  // ── Patch Results ──
  if (result.patch_results && result.patch_results.length > 0) {
    lines.push("## Patch Proposals");
    lines.push("");
    lines.push("| # | Finding | Status | File |");
    lines.push("|---|---------|--------|------|");

    for (let i = 0; i < result.patch_results.length; i++) {
      const pr = result.patch_results[i];
      const statusLabel = pr.status === "patched_and_verified" ? "APPROVED"
        : pr.status === "patched_needs_review" ? "NEEDS REVIEW"
        : pr.status === "patch_rejected" ? "REJECTED"
        : pr.status;
      const file = pr.patch?.file ? path.basename(pr.patch.file) : "-";
      lines.push(`| ${i + 1} | ${pr.adversarial.finding.title} | **${statusLabel}** | \`${file}\` |`);
    }
    lines.push("");

    const approved = result.patch_results.filter((r) => r.status === "patched_and_verified");
    if (approved.length > 0) {
      lines.push("### Approved Patches");
      lines.push("");
      for (const pr of approved) {
        lines.push(`**${pr.adversarial.finding.title}**`);
        lines.push(`- Root cause: ${pr.patch!.root_cause}`);
        lines.push(`- Explanation: ${pr.patch!.explanation}`);
        lines.push("```diff");
        lines.push(pr.patch!.patch_diff);
        lines.push("```");
        lines.push("");
      }
    }
  }

  // ── Footer ──
  lines.push("---");
  lines.push(`*Report generated by Hydra Security v0.1.0*`);
  lines.push("");

  return lines.join("\n");
}
