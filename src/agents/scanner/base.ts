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
