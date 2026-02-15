import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding, Severity, VulnClass } from "../../types";

export interface Scanner {
  id: string;
  scan(rootPath: string): Promise<Finding[]>;
}

export async function listFilesRecursive(
  root: string,
  filePredicate: (filePath: string) => boolean
): Promise<string[]> {
  const out: string[] = [];

  async function walk(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (filePredicate(fullPath)) {
        out.push(fullPath);
      }
    }
  }

  await walk(root);
  return out;
}

export function findLineContaining(content: string, needle: string): number {
  const lines = content.split(/\r?\n/);
  const idx = lines.findIndex((line) => line.includes(needle));
  return idx >= 0 ? idx + 1 : 1;
}

export function marker(classTag: string): string {
  return `HYDRA_VULN:${classTag}`;
}

export function makeFinding(input: {
  scannerId: string;
  vulnClass: VulnClass;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  title: string;
  description: string;
  evidence: string;
}): Finding {
  const idSeed = `${input.scannerId}|${input.vulnClass}|${input.file}|${input.line}`;
  const id = createHash("sha256").update(idSeed).digest("hex").slice(0, 16);

  return {
    id,
    scanner_id: input.scannerId,
    vuln_class: input.vulnClass,
    severity: input.severity,
    confidence: input.confidence,
    file: input.file,
    line: input.line,
    title: input.title,
    description: input.description,
    evidence: input.evidence
  };
}

export interface PatternRule {
  vulnClass: VulnClass;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  /** Regex to match on a single line */
  pattern: RegExp;
  /** If any of these appear within contextLines of the match, suppress the finding */
  mitigations?: RegExp[];
  /** Lines before/after to check for mitigations (default: 5) */
  contextLines?: number;
}

export function scanFileWithPatterns(
  scannerId: string,
  filePath: string,
  content: string,
  rules: PatternRule[]
): Finding[] {
  const lines = content.split(/\r?\n/);
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of rules) {
    for (let i = 0; i < lines.length; i++) {
      if (!rule.pattern.test(lines[i])) continue;

      // Deduplicate same vuln class at same line
      const dedup = `${rule.vulnClass}:${i}`;
      if (seen.has(dedup)) continue;

      // Check mitigations in context window
      if (rule.mitigations && rule.mitigations.length > 0) {
        const window = rule.contextLines ?? 5;
        const start = Math.max(0, i - window);
        const end = Math.min(lines.length, i + window + 1);
        const context = lines.slice(start, end).join("\n");

        if (rule.mitigations.some((m) => m.test(context))) continue;
      }

      seen.add(dedup);
      const matched = lines[i].trim();
      findings.push(
        makeFinding({
          scannerId,
          vulnClass: rule.vulnClass,
          severity: rule.severity,
          confidence: rule.confidence,
          file: filePath,
          line: i + 1,
          title: rule.title,
          description: rule.description,
          evidence: matched.length > 120 ? `${matched.slice(0, 117)}...` : matched
        })
      );
    }
  }

  return findings;
}
