import { promises as fs } from "node:fs";
import type { Finding } from "../../types";
import { listFilesRecursive } from "./base";
import { LlmClient, type LlmClientOptions } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget, truncateToTokenBudget, estimateTokens } from "../../llm/token-budget";
import { parseFindingsResponse } from "../../llm/parser";

export interface LlmScannerOptions {
  vulnFocus: string;
  scannerId: string;
  clientOptions?: LlmClientOptions;
}

const MAX_FILE_SIZE_BYTES = 256_000;

export async function runLlmScanner(
  rootPath: string,
  options: LlmScannerOptions
): Promise<Finding[]> {
  const route = routeModelWithFallbacks("scanner");
  const budget = computeTokenBudget(route.primary, "scanner");
  const client = new LlmClient({
    ...options.clientOptions,
    fallbackModels: route.fallbacks
  });

  const files = await listFilesRecursive(rootPath, (f) => f.endsWith(".rs"));
  const findings: Finding[] = [];

  for (const filePath of files) {
    const stat = await fs.stat(filePath);
    if (stat.size > MAX_FILE_SIZE_BYTES) continue;

    const code = await fs.readFile(filePath, "utf8");
    if (estimateTokens(code) < 10) continue;

    const truncated = truncateToTokenBudget(code, budget.maxInputTokens - 500);
    const rendered = renderPrompt("scanner", {
      vuln_focus: options.vulnFocus,
      file_path: filePath,
      code: truncated.text
    });

    const response = await client.createMessage({
      model: route.primary,
      system: rendered.system,
      messages: [{ role: "user", content: rendered.user }],
      max_tokens: budget.maxOutputTokens,
      temperature: 0.2
    });

    const parsed = parseFindingsResponse(response.content, options.scannerId);

    for (const finding of parsed.findings) {
      findings.push({
        ...finding,
        file: filePath
      });
    }
  }

  return findings;
}

export const LLM_SCANNER_CONFIGS = [
  {
    vulnFocus: "missing signer check, missing has_one constraint, and account type confusion",
    scannerId: "llm.scanner.solana.account-validation"
  },
  {
    vulnFocus: "arbitrary CPI, CPI signer seed bypass, and CPI reentrancy",
    scannerId: "llm.scanner.solana.cpi"
  },
  {
    vulnFocus: "non-canonical bump, seed collision, and attacker-controlled seed",
    scannerId: "llm.scanner.solana.pda"
  }
] as const;

export async function runAllLlmScanners(
  rootPath: string,
  clientOptions?: LlmClientOptions
): Promise<Finding[]> {
  const allFindings: Finding[] = [];

  for (const config of LLM_SCANNER_CONFIGS) {
    const findings = await runLlmScanner(rootPath, {
      vulnFocus: config.vulnFocus,
      scannerId: config.scannerId,
      clientOptions
    });
    allFindings.push(...findings);
  }

  return allFindings;
}
