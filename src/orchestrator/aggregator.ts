import type { Finding } from "../types";

export function aggregateFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.vuln_class}|${finding.file}|${finding.line}`;
    const existing = byKey.get(key);
    if (!existing || finding.confidence > existing.confidence) {
      byKey.set(key, finding);
    }
  }

  return [...byKey.values()].sort((a, b) => b.confidence - a.confidence);
}
