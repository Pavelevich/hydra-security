import type { Finding, ScanTarget } from "../types";
import { solanaAccountValidationScanner } from "../agents/scanner/solana-account-validation";
import { solanaCpiScanner } from "../agents/scanner/solana-cpi";
import { solanaPdaScanner } from "../agents/scanner/solana-pda";

const scanners = [solanaAccountValidationScanner, solanaCpiScanner, solanaPdaScanner];

export async function dispatchScanners(target: ScanTarget): Promise<Finding[]> {
  const settled = await Promise.allSettled(scanners.map((scanner) => scanner.scan(target.root_path)));
  const findings: Finding[] = [];

  for (const result of settled) {
    if (result.status === "fulfilled") {
      findings.push(...result.value);
    }
  }

  return findings;
}
