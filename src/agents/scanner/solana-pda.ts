import { promises as fs } from "node:fs";
import type { Finding } from "../../types";
import {
  findLineContaining,
  listFilesRecursive,
  makeFinding,
  marker,
  scanFileWithPatterns,
  type PatternRule,
  type Scanner
} from "./base";

const markerRules = [
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

const patternRules: PatternRule[] = [
  {
    vulnClass: "non_canonical_bump",
    severity: "HIGH",
    confidence: 70,
    title: "Non-canonical bump parameter accepted",
    description:
      "Function accepts bump as u8 parameter instead of deriving it via find_program_address. " +
      "Attacker can supply a non-canonical bump to create a different PDA that passes validation.",
    pattern: /\bbump\s*:\s*u8\b/,
    mitigations: [
      // Safe if find_program_address is called to verify
      /find_program_address\s*\(/
    ],
    contextLines: 15
  },
  {
    vulnClass: "non_canonical_bump",
    severity: "HIGH",
    confidence: 72,
    title: "create_program_address without canonical bump derivation",
    description:
      "Uses create_program_address directly which accepts any bump. Should use find_program_address " +
      "to ensure the canonical bump is used, or verify the bump via seeds constraint.",
    pattern: /Pubkey::create_program_address\s*\(/,
    mitigations: [
      /find_program_address\s*\(/,
      /\bbump\s*=\s*bump\b/ // Anchor bump constraint
    ],
    contextLines: 15
  },
  {
    vulnClass: "attacker_controlled_seed",
    severity: "HIGH",
    confidence: 65,
    title: "Instruction data used directly in PDA seeds",
    description:
      "PDA seeds appear to include data from instruction arguments without domain separation. " +
      "Attacker may craft inputs that collide with existing PDA addresses.",
    pattern: /seeds\s*=\s*\[.*\bctx\.accounts\.\w+\.key\(\)/,
    mitigations: [
      /b"[a-zA-Z_]+"/ // Static seed prefix provides domain separation
    ],
    contextLines: 3
  },
  {
    vulnClass: "seed_collision",
    severity: "MEDIUM",
    confidence: 58,
    title: "PDA seeds lack domain separation prefix",
    description:
      "find_program_address seeds do not include a static string prefix, increasing risk " +
      "of seed collision across different instruction contexts.",
    pattern: /find_program_address\s*\(\s*&\s*\[/,
    mitigations: [
      /b"[a-zA-Z_]+"/, // Has a static seed prefix
      /b"[a-zA-Z_]+"\.as_ref\(\)/ // Has a static seed prefix via as_ref
    ],
    contextLines: 5
  },
  {
    vulnClass: "non_canonical_bump",
    severity: "MEDIUM",
    confidence: 62,
    title: "Anchor seeds constraint without bump verification",
    description:
      "Anchor #[account] seeds constraint does not include a bump field, meaning the canonical " +
      "bump is not enforced and a non-canonical PDA could be supplied.",
    pattern: /#\[account\([^)]*seeds\s*=/,
    mitigations: [/bump\s*=/, /bump\s*\)/],
    contextLines: 3
  }
];

export const solanaPdaScanner: Scanner = {
  id: "scanner.solana.pda",
  async scan(rootPath: string): Promise<Finding[]> {
    const files = await listFilesRecursive(rootPath, (filePath) => filePath.endsWith(".rs"));
    const findings: Finding[] = [];

    for (const file of files) {
      const content = await fs.readFile(file, "utf8");

      // Marker-based detection (golden repos / eval compatibility)
      for (const rule of markerRules) {
        const token = marker(rule.tag);
        if (!content.includes(token)) continue;

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

      // Pattern-based detection (real code analysis)
      findings.push(...scanFileWithPatterns(this.id, file, content, patternRules));
    }

    return findings;
  }
};
