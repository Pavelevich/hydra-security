import { promises as fs } from "node:fs";
import type { Finding } from "../../types";
import { findLineContaining, listFilesRecursive, makeFinding, marker, type Scanner } from "./base";

const rules = [
  {
    tag: "arbitrary_cpi",
    title: "Arbitrary CPI target risk",
    description:
      "Program appears to allow user-controlled CPI target, which may permit malicious invocation."
  },
  {
    tag: "cpi_signer_seed_bypass",
    title: "Signer seed validation weakness in CPI",
    description:
      "CPI signer seed handling appears weak and may permit authority bypass."
  },
  {
    tag: "cpi_reentrancy",
    title: "Potential CPI reentrancy path",
    description: "Instruction flow appears vulnerable to callback-based reentrancy."
  }
] as const;

export const solanaCpiScanner: Scanner = {
  id: "scanner.solana.cpi",
  async scan(rootPath: string): Promise<Finding[]> {
    const files = await listFilesRecursive(rootPath, (filePath) => filePath.endsWith(".rs"));
    const findings: Finding[] = [];

    for (const file of files) {
      const content = await fs.readFile(file, "utf8");

      for (const rule of rules) {
        const token = marker(rule.tag);
        if (!content.includes(token)) {
          continue;
        }
        findings.push(
          makeFinding({
            scannerId: this.id,
            vulnClass: rule.tag,
            severity: "CRITICAL",
            confidence: 90,
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
};
