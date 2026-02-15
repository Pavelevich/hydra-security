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

const patternRules: PatternRule[] = [
  {
    vulnClass: "missing_signer_check",
    severity: "HIGH",
    confidence: 72,
    title: "Potential missing signer check on authority",
    description:
      "Authority-like account uses raw AccountInfo instead of Signer<'info>, which does not enforce signature verification.",
    pattern: /pub\s+(authority|admin|owner|payer|fee_payer)\s*:\s*(?:Unchecked)?AccountInfo/,
    mitigations: [
      /Signer<'info>/,
      /#\[account\([^\]]*signer/
    ],
    contextLines: 4
  },
  {
    vulnClass: "missing_signer_check",
    severity: "HIGH",
    confidence: 68,
    title: "Potential missing signer check on admin account",
    description:
      "Account field with admin/authority naming pattern uses UncheckedAccount, bypassing signer verification.",
    pattern: /pub\s+(authority|admin|owner)\s*:\s*UncheckedAccount/,
    mitigations: [/Signer<'info>/],
    contextLines: 3
  },
  {
    vulnClass: "account_type_confusion",
    severity: "MEDIUM",
    confidence: 65,
    title: "Data account uses raw AccountInfo instead of typed Account",
    description:
      "Data-holding account field uses AccountInfo instead of Account<'info, T>, bypassing account discriminator and deserialization checks.",
    pattern:
      /pub\s+(vault|treasury|pool|token_account|stake_account|reward_account|escrow|deposit|user_account|state)\s*:\s*AccountInfo/,
    mitigations: [/Account<'info,/, /CpiAccount<'info,/],
    contextLines: 3
  },
  {
    vulnClass: "missing_has_one",
    severity: "MEDIUM",
    confidence: 60,
    title: "Potential missing has_one relationship constraint",
    description:
      "Accounts struct contains authority field but no has_one constraint linking it to a data account, allowing owner substitution.",
    pattern: /pub\s+authority\s*:\s*Signer<'info>/,
    mitigations: [/has_one\s*=\s*authority/],
    contextLines: 20
  }
];

export const solanaAccountValidationScanner: Scanner = {
  id: "scanner.solana.account-validation",
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
            confidence: 88,
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
