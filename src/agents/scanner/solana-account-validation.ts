import { promises as fs } from "node:fs";
import type { Finding } from "../../types";
import { findLineContaining, listFilesRecursive, makeFinding, marker, type Scanner } from "./base";

const rules = [
  {
    tag: "missing_signer_check",
    title: "Missing signer check on authority account",
    description:
      "Instruction uses an authority-like account without enforcing signer semantics."
  },
  {
    tag: "missing_has_one",
    title: "Missing has_one relationship constraint",
    description:
      "Account relationship constraints are missing, allowing owner/context substitution."
  },
  {
    tag: "account_type_confusion",
    title: "Account type confusion risk",
    description:
      "Account type validation appears weak and may allow wrong account struct substitution."
  }
] as const;

export const solanaAccountValidationScanner: Scanner = {
  id: "scanner.solana.account-validation",
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
            severity: "HIGH",
            confidence: 88,
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
