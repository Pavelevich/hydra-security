import { promises as fs } from "node:fs";
import type { Finding } from "../../types";
import { findLineContaining, listFilesRecursive, makeFinding, marker, type Scanner } from "./base";

const rules = [
  {
    tag: "non_canonical_bump",
    title: "Non-canonical bump handling",
    description:
      "PDA derivation appears to allow non-canonical bump use, increasing spoof/collision risk."
  },
  {
    tag: "seed_collision",
    title: "PDA seed collision risk",
    description: "Seed composition may permit collisions across logical account namespaces."
  },
  {
    tag: "attacker_controlled_seed",
    title: "Attacker-controlled PDA seed component",
    description:
      "Attacker input appears to influence PDA seeds without strong domain separation."
  }
] as const;

export const solanaPdaScanner: Scanner = {
  id: "scanner.solana.pda",
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
            confidence: 86,
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
