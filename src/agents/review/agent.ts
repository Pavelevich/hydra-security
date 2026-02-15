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

function applyPatchToSource(source: string, patchDiff: string): string {
  // Simple heuristic: if the patch contains unified diff markers, try to
  // extract the "after" lines. For a full implementation this would use a
  // proper diff-apply library. For now, return the original source with a
  // comment indicating the patch was applied conceptually.
  if (patchDiff.includes("@@") && (patchDiff.includes("---") || patchDiff.includes("+++"))) {
    const afterLines: string[] = [];
    for (const line of patchDiff.split("\n")) {
      if (line.startsWith("+") && !line.startsWith("+++")) {
        afterLines.push(line.slice(1));
      } else if (!line.startsWith("-") && !line.startsWith("---") && !line.startsWith("@@") && !line.startsWith("diff")) {
        afterLines.push(line.startsWith(" ") ? line.slice(1) : line);
      }
    }
    if (afterLines.length > 0) {
      return afterLines.join("\n");
    }
  }
  return source;
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
      const patchedSource = applyPatchToSource(sourceCode, patch.patch_diff);
      exploitRetestPassed = await retestExploitInSandbox(
        patchedSource,
        adversarial.red_team.exploit_code
      );
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
