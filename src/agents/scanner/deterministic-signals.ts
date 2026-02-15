import { promises as fs } from "node:fs";
import type { Finding, Severity, VulnClass } from "../../types";
import { listFilesRecursive, makeFinding } from "./base";

interface DeterministicSignalRule {
  id: string;
  vulnClass: VulnClass;
  severity: Severity;
  confidence: number;
  title: string;
  description: string;
  regex: RegExp;
}

const rules: DeterministicSignalRule[] = [
  {
    id: "rule.missing-signer-accountinfo",
    vulnClass: "missing_signer_check",
    severity: "HIGH",
    confidence: 62,
    title: "Potential missing signer check",
    description: "Detected AccountInfo authority/admin pattern without deterministic signer guarantee.",
    regex: /\bpub\s+(authority|admin)\s*:\s*AccountInfo<'info>/
  },
  {
    id: "rule.user-controlled-cpi-target",
    vulnClass: "arbitrary_cpi",
    severity: "CRITICAL",
    confidence: 65,
    title: "Potential arbitrary CPI target",
    description: "Detected likely user-controlled CPI target parameter pattern.",
    regex: /\btarget_program\s*:\s*Pubkey\b/
  },
  {
    id: "rule.non-canonical-bump-param",
    vulnClass: "non_canonical_bump",
    severity: "HIGH",
    confidence: 60,
    title: "Potential non-canonical bump handling",
    description: "Detected raw bump parameter pattern requiring canonical bump validation audit.",
    regex: /\bbump\s*:\s*u8\b/
  }
];

function snippet(line: string): string {
  const trimmed = line.trim();
  return trimmed.length > 160 ? `${trimmed.slice(0, 157)}...` : trimmed;
}

export async function runDeterministicSignalAdapters(rootPath: string): Promise<Finding[]> {
  const files = await listFilesRecursive(rootPath, (filePath) => filePath.endsWith(".rs"));
  const findings: Finding[] = [];

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    const lines = content.split(/\r?\n/);

    for (const rule of rules) {
      const index = lines.findIndex((line) => rule.regex.test(line));
      if (index < 0) {
        continue;
      }

      findings.push(
        makeFinding({
          scannerId: `signal.deterministic.${rule.id}`,
          vulnClass: rule.vulnClass,
          severity: rule.severity,
          confidence: rule.confidence,
          file,
          line: index + 1,
          title: rule.title,
          description: rule.description,
          evidence: `Matched regex ${rule.regex.toString()} on: ${snippet(lines[index] ?? "")}`
        })
      );
    }
  }

  return findings;
}
