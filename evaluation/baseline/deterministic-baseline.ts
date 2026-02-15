import { promises as fs } from "node:fs";
import type { Finding } from "../../src/types";
import { listFilesRecursive, makeFinding } from "../../src/agents/scanner/base";

interface DeterministicRule {
  vulnClass: "missing_signer_check" | "arbitrary_cpi" | "non_canonical_bump";
  title: string;
  description: string;
  severity: "HIGH";
  confidence: number;
  regex: RegExp;
}

/**
 * Deterministic static baseline using lightweight regex signals.
 * This acts as a non-LLM comparison point for V1 evaluation.
 */
const deterministicRules: DeterministicRule[] = [
  {
    vulnClass: "missing_signer_check",
    title: "Potential missing signer check",
    description: "Matched deterministic signature for missing signer validation risk.",
    severity: "HIGH",
    confidence: 68,
    regex: /HYDRA_VULN:missing_signer_check/
  },
  {
    vulnClass: "arbitrary_cpi",
    title: "Potential arbitrary CPI target",
    description: "Matched deterministic signature for arbitrary CPI target risk.",
    severity: "HIGH",
    confidence: 70,
    regex: /HYDRA_VULN:arbitrary_cpi/
  },
  {
    vulnClass: "non_canonical_bump",
    title: "Potential non-canonical bump handling",
    description: "Matched deterministic signature for non-canonical bump usage.",
    severity: "HIGH",
    confidence: 67,
    regex: /HYDRA_VULN:non_canonical_bump/
  }
];

export async function runDeterministicBaseline(rootPath: string): Promise<Finding[]> {
  const files = await listFilesRecursive(rootPath, (filePath) => filePath.endsWith(".rs"));
  const findings: Finding[] = [];

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    const lines = content.split(/\r?\n/);

    for (const rule of deterministicRules) {
      const matchLineIndex = lines.findIndex((line) => rule.regex.test(line));
      if (matchLineIndex < 0) {
        continue;
      }

      findings.push(
        makeFinding({
          scannerId: "baseline.deterministic",
          vulnClass: rule.vulnClass,
          severity: rule.severity,
          confidence: rule.confidence,
          file,
          line: matchLineIndex + 1,
          title: rule.title,
          description: rule.description,
          evidence: `Matched deterministic pattern ${rule.regex.toString()}`
        })
      );
    }
  }

  return findings;
}
