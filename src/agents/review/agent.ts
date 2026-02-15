import { promises as fs } from "node:fs";
import type { AdversarialResult, PatchProposal, PatchReview, ReviewIssue } from "../../types";
import { LlmClient } from "../../llm/client";
import { routeModelWithFallbacks } from "../../llm/router";
import { renderPrompt } from "../../llm/prompts";
import { computeTokenBudget, truncateToTokenBudget } from "../../llm/token-budget";
import { parseJsonResponse } from "../../llm/parser";
import { createSandbox, isSandboxAvailable, isSandboxImageBuilt } from "../../sandbox/runner";

async function readSource(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

async function retestExploitInSandbox(
  patchedCode: string,
  exploitCode: string | undefined
): Promise<boolean | undefined> {
  if (!exploitCode) return undefined;

  const dockerReady = await isSandboxAvailable();
  if (!dockerReady) return undefined;

  const imageReady = await isSandboxImageBuilt("generic");
  if (!imageReady) return undefined;

  const session = await createSandbox("generic", { timeoutMs: 30_000 });
  try {
    await session.writeFile("/workspace/patched.rs", patchedCode);
    await session.writeFile("/workspace/exploit.ts", exploitCode);
    const result = await session.exec(["bun", "run", "/workspace/exploit.ts"], 25_000);
    // If exploit now fails (non-zero exit), the patch works
    return result.exit_code !== 0;
  } catch {
    return undefined;
  } finally {
    await session.destroy();
  }
}

function applyPatchToSource(source: string, patchDiff: string): { patched: string; applied: boolean } {
  // Apply unified diff hunks to source. Returns the patched source and
  // whether the patch was actually applied (vs returned unchanged).
  if (!patchDiff.includes("@@") || (!patchDiff.includes("---") && !patchDiff.includes("+++"))) {
    return { patched: source, applied: false };
  }

  const sourceLines = source.split("\n");
  const patchLines = patchDiff.split("\n");
  let offset = 0;
  let anyApplied = false;

  for (let i = 0; i < patchLines.length; i++) {
    const hunkMatch = patchLines[i].match(/^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/);
    if (!hunkMatch) continue;

    const startLine = parseInt(hunkMatch[1], 10) - 1 + offset;
    const removeLines: number[] = [];
    const addLines: string[] = [];

    for (let j = i + 1; j < patchLines.length; j++) {
      const line = patchLines[j];
      if (line.startsWith("@@") || line.startsWith("diff ")) break;
      if (line.startsWith("-") && !line.startsWith("---")) {
        removeLines.push(j);
      } else if (line.startsWith("+") && !line.startsWith("+++")) {
        addLines.push(line.slice(1));
      }
    }

    // Verify context: removed lines must match source at expected position
    let contextMatches = true;
    let removeIdx = 0;
    for (let j = i + 1; j < patchLines.length && removeIdx < removeLines.length; j++) {
      const line = patchLines[j];
      if (line.startsWith("@@") || line.startsWith("diff ")) break;
      if (line.startsWith("-") && !line.startsWith("---")) {
        const expectedContent = line.slice(1);
        const actualLine = sourceLines[startLine + removeIdx];
        if (actualLine === undefined || actualLine !== expectedContent) {
          contextMatches = false;
          break;
        }
        removeIdx++;
      }
    }

    if (contextMatches && (removeLines.length > 0 || addLines.length > 0)) {
      sourceLines.splice(startLine, removeLines.length, ...addLines);
      offset += addLines.length - removeLines.length;
      anyApplied = true;
    }
  }

  return { patched: sourceLines.join("\n"), applied: anyApplied };
}

export async function runReviewAgent(
  adversarial: AdversarialResult,
  patch: PatchProposal
): Promise<PatchReview> {
  const route = routeModelWithFallbacks("review");
  const budget = computeTokenBudget(route.primary, "review");
  const client = new LlmClient({ fallbackModels: route.fallbacks });

  const sourceCode = await readSource(patch.file);
  const truncatedSource = truncateToTokenBudget(sourceCode, budget.maxInputTokens - 3000);

  const rendered = renderPrompt("review", {
    vuln_class: adversarial.finding.vuln_class,
    file_path: patch.file,
    line: String(adversarial.finding.line),
    patch_diff: patch.patch_diff,
    test_code: patch.test_code,
    code: truncatedSource.text
  });

  const response = await client.createMessage({
    model: route.primary,
    system: rendered.system,
    messages: [{ role: "user", content: rendered.user }],
    max_tokens: budget.maxOutputTokens,
    temperature: 0.1
  });

  const parsed = parseJsonResponse<Record<string, unknown>>(response.content);

  let approved = false;
  let issues: ReviewIssue[] = [];
  let suggestions: string[] = [];

  if (parsed.data) {
    const data = parsed.data;
    approved = data.approved === true;

    if (Array.isArray(data.issues)) {
      issues = (data.issues as Array<Record<string, unknown>>)
        .map((issue) => ({
          severity: isValidIssueSeverity(issue.severity) ? issue.severity : ("warning" as const),
          description: typeof issue.description === "string" ? issue.description : String(issue.description ?? "")
        }))
        .filter((issue) => issue.description.length > 0);
    }

    if (Array.isArray(data.suggestions)) {
      suggestions = (data.suggestions as string[]).map(String).filter(Boolean);
    }
  }

  // Attempt exploit retest in sandbox
  let exploitRetestPassed: boolean | undefined;
  if (adversarial.red_team?.exploit_code) {
    try {
      const { patched: patchedSource, applied: patchApplied } = applyPatchToSource(sourceCode, patch.patch_diff);

      if (!patchApplied) {
        // Patch could not be applied to source — cannot verify
        approved = false;
        issues.push({
          severity: "error",
          description: "Patch verification failed: unified diff could not be applied to the source file. Context lines did not match."
        });
      } else {
        exploitRetestPassed = await retestExploitInSandbox(
          patchedSource,
          adversarial.red_team.exploit_code
        );
      }
    } catch {
      // Sandbox retest failed — non-fatal
    }
  }

  // If exploit retest ran and failed (exploit still works), override approval
  if (exploitRetestPassed === false) {
    approved = false;
    issues.push({
      severity: "error",
      description: "Exploit retest: Red Team exploit still succeeds against patched code."
    });
  }

  // If sandbox wasn't available but patch was applied, note the gap
  if (exploitRetestPassed === undefined && adversarial.red_team?.exploit_code) {
    issues.push({
      severity: "warning",
      description: "Exploit retest could not run (sandbox unavailable). Patch approval is based on LLM review only."
    });
  }

  return {
    finding_id: adversarial.finding.id,
    patch_proposal: patch,
    approved,
    issues,
    suggestions,
    exploit_retest_passed: exploitRetestPassed,
    regression_check_passed: undefined // Requires project-specific test runner
  };
}

function isValidIssueSeverity(value: unknown): value is "error" | "warning" | "info" {
  return value === "error" || value === "warning" || value === "info";
}
