import type { Finding } from "../types";

const severityRank: Record<Finding["severity"], number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1
};

const MIN_UNCORROBORATED_CONFIDENCE = 80;

function mergeEvidence(a: string, b: string): string {
  if (a === b) {
    return a;
  }
  return `${a}\n${b}`;
}

function mergeDescription(a: string, b: string): string {
  if (a === b) {
    return a;
  }
  return `${a} | ${b}`;
}

function mergeScannerIds(a: string, b: string): string {
  const ids = new Set([...a.split(" + "), ...b.split(" + ")].filter(Boolean));
  return [...ids].join(" + ");
}

function mergedConfidence(existing: number, incoming: number, corroborated: boolean): number {
  const top = Math.max(existing, incoming);
  if (!corroborated) {
    return top;
  }
  return Math.min(99, top + 5);
}

function isCorroborated(scannerId: string): boolean {
  return scannerId.includes(" + ");
}

function shouldEmitFinding(finding: Finding): boolean {
  return isCorroborated(finding.scanner_id) || finding.confidence >= MIN_UNCORROBORATED_CONFIDENCE;
}

export function aggregateFindings(findings: Finding[]): Finding[] {
  const byKey = new Map<string, Finding>();

  for (const finding of findings) {
    const key = `${finding.vuln_class}|${finding.file}|${finding.line}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, finding);
      continue;
    }

    const corroborated = existing.scanner_id !== finding.scanner_id;
    const winner =
      severityRank[finding.severity] > severityRank[existing.severity] ? finding : existing;

    const merged: Finding = {
      ...winner,
      scanner_id: mergeScannerIds(existing.scanner_id, finding.scanner_id),
      confidence: mergedConfidence(existing.confidence, finding.confidence, corroborated),
      evidence: mergeEvidence(existing.evidence, finding.evidence),
      description: mergeDescription(existing.description, finding.description)
    };

    if (merged.scanner_id.includes(" + ") && !merged.title.endsWith("(corroborated)")) {
      merged.title = `${merged.title} (corroborated)`;
    }

    byKey.set(key, merged);
  }

  return [...byKey.values()].filter(shouldEmitFinding).sort((a, b) => {
    const bySeverity = severityRank[b.severity] - severityRank[a.severity];
    if (bySeverity !== 0) {
      return bySeverity;
    }
    return b.confidence - a.confidence;
  });
}
