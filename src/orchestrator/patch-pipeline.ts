import type { AdversarialResult, PatchResult } from "../types";
import { runPatchAgent } from "../agents/patch/agent";
import { runReviewAgent } from "../agents/review/agent";

export interface PatchPipelineOptions {
  maxConcurrent?: number;
  skipReview?: boolean;
}

const DEFAULT_MAX_CONCURRENT = 2;

async function processOne(
  adversarial: AdversarialResult,
  skipReview: boolean
): Promise<PatchResult> {
  const verdict = adversarial.judge?.verdict;
  if (verdict !== "confirmed" && verdict !== "likely") {
    return { adversarial, status: "skipped" };
  }

  const patch = await runPatchAgent(adversarial);
  if (!patch || !patch.patch_diff) {
    return { adversarial, status: "no_patch" };
  }

  if (skipReview) {
    return { adversarial, patch, status: "patched_needs_review" };
  }

  const review = await runReviewAgent(adversarial, patch);

  if (review.approved) {
    return { adversarial, patch, review, status: "patched_and_verified" };
  }

  return { adversarial, patch, review, status: "patch_rejected" };
}

export async function runPatchPipeline(
  adversarialResults: AdversarialResult[],
  options: PatchPipelineOptions = {}
): Promise<PatchResult[]> {
  const maxConcurrent = options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
  const skipReview = options.skipReview ?? false;

  const eligible = adversarialResults.filter((r) => {
    const v = r.judge?.verdict;
    return v === "confirmed" || v === "likely";
  });

  if (eligible.length === 0) return [];

  const results: PatchResult[] = [];
  const queue = [...eligible];
  const running = new Set<Promise<void>>();

  const processNext = (): void => {
    const item = queue.shift();
    if (!item) return;

    let taskPromise: Promise<void>;
    taskPromise = processOne(item, skipReview)
      .then((result) => { results.push(result); })
      .catch(() => { results.push({ adversarial: item, status: "no_patch" }); })
      .finally(() => running.delete(taskPromise));

    running.add(taskPromise);
  };

  while (queue.length > 0 || running.size > 0) {
    while (queue.length > 0 && running.size < maxConcurrent) {
      processNext();
    }
    if (running.size > 0) {
      await Promise.race(running);
    }
  }

  return results;
}
