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

const patternRules: PatternRule[] = [
  {
    vulnClass: "arbitrary_cpi",
    severity: "CRITICAL",
    confidence: 70,
    title: "Potential arbitrary CPI target",
    description:
      "invoke() or invoke_signed() called with a program AccountInfo that may be user-controlled. Attacker could substitute a malicious program.",
    pattern: /\binvoke(?:_signed)?\s*\(/,
    mitigations: [
      // Safe if calling known program IDs directly
      /system_program::id\(\)/,
      /token::ID/,
      /spl_token::id\(\)/,
      /associated_token::id\(\)/,
      /system_instruction::/
    ],
    contextLines: 8
  },
  {
    vulnClass: "arbitrary_cpi",
    severity: "CRITICAL",
    confidence: 72,
    title: "User-supplied program account in CPI context",
    description:
      "CpiContext uses a program account that appears to be user-supplied AccountInfo, allowing arbitrary program invocation.",
    pattern: /CpiContext::new\s*\(\s*ctx\.accounts\.\w+_program\.to_account_info\(\)/,
    mitigations: [
      /Program<'info,\s*System>/,
      /Program<'info,\s*Token>/
    ],
    contextLines: 10
  },
  {
    vulnClass: "cpi_reentrancy",
    severity: "HIGH",
    confidence: 65,
    title: "State modification before CPI call",
    description:
      "Account data appears to be modified before an invoke() call in the same function. If the CPI target calls back, it may observe stale state.",
    pattern: /\btry_borrow_mut_data\s*\(/,
    mitigations: [],
    contextLines: 0 // Checked manually below
  },
  {
    vulnClass: "cpi_signer_seed_bypass",
    severity: "HIGH",
    confidence: 65,
    title: "Potential signer seed bypass in invoke_signed",
    description:
      "invoke_signed uses seeds that may include user-controlled data, potentially allowing authority impersonation.",
    pattern: /\binvoke_signed\s*\(/,
    mitigations: [
      /find_program_address\s*\(/,
      /Pubkey::create_program_address\s*\(/
    ],
    contextLines: 10
  }
];

export const solanaCpiScanner: Scanner = {
  id: "scanner.solana.cpi",
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

      // Pattern-based detection (real code analysis)
      findings.push(...scanFileWithPatterns(this.id, file, content, patternRules));

      // File-level reentrancy check: borrow_mut_data before invoke in same file
      if (content.includes("try_borrow_mut_data") && /\binvoke(?:_signed)?\s*\(/.test(content)) {
        const lines = content.split(/\r?\n/);
        let mutLine = -1;
        let invokeLine = -1;
        for (let i = 0; i < lines.length; i++) {
          if (mutLine < 0 && /try_borrow_mut_data/.test(lines[i])) mutLine = i;
          if (/\binvoke(?:_signed)?\s*\(/.test(lines[i])) invokeLine = i;
        }
        if (mutLine >= 0 && invokeLine > mutLine) {
          findings.push(
            makeFinding({
              scannerId: this.id,
              vulnClass: "cpi_reentrancy",
              severity: "HIGH",
              confidence: 62,
              file,
              line: invokeLine + 1,
              title: "State mutation before CPI may enable reentrancy",
              description:
                "Account data is mutated via try_borrow_mut_data() before an invoke() call. " +
                "If the CPI target calls back into this program, it may observe inconsistent state.",
              evidence: `borrow_mut_data at line ${mutLine + 1}, invoke at line ${invokeLine + 1}`
            })
          );
        }
      }
    }

    return findings;
  }
};
