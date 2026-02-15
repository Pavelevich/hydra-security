import { promises as fs } from "node:fs";
import type { Finding } from "../../src/types";
import { findLineContaining, listFilesRecursive, makeFinding, marker } from "../../src/agents/scanner/base";

/**
 * Baseline intentionally uses a narrower detector set to represent
 * a single-loop generic scanner with lower Solana specialization.
 */
const baselineRules = [
  {
    tag: "missing_signer_check" as const,
    severity: "HIGH" as const,
    confidence: 75,
    title: "Potential missing signer check",
    description: "Baseline detected possible missing signer validation."
  },
  {
    tag: "arbitrary_cpi" as const,
    severity: "HIGH" as const,
    confidence: 70,
    title: "Potential arbitrary CPI target",
    description: "Baseline detected possible dynamic CPI target risk."
  }
];

export async function runSingleAgentBaseline(rootPath: string): Promise<Finding[]> {
  const files = await listFilesRecursive(rootPath, (filePath) => filePath.endsWith(".rs"));
  const findings: Finding[] = [];

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    for (const rule of baselineRules) {
      const token = marker(rule.tag);
      if (!content.includes(token)) {
        continue;
      }

      findings.push(
        makeFinding({
          scannerId: "baseline.single-agent",
          vulnClass: rule.tag,
          severity: rule.severity,
          confidence: rule.confidence,
          file,
          line: findLineContaining(content, token),
          title: rule.title,
          description: rule.description,
          evidence: `Found marker ${token}`
        })
      );
    }
  }

  return findings;
}
