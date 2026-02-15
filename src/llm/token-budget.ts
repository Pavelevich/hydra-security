import type { AgentTask } from "./router";

export interface ModelLimits {
  contextWindow: number;
  maxOutputTokens: number;
}

export interface TokenBudget {
  model: string;
  maxInputTokens: number;
  maxOutputTokens: number;
  reservedForSystem: number;
}

const MODEL_LIMITS: Record<string, ModelLimits> = {
  "claude-opus-4-6-20250605": { contextWindow: 200_000, maxOutputTokens: 32_000 },
  "claude-sonnet-4-5-20250929": { contextWindow: 200_000, maxOutputTokens: 64_000 },
  "claude-haiku-4-5-20251001": { contextWindow: 200_000, maxOutputTokens: 64_000 }
};

const SYSTEM_PROMPT_RESERVE_TOKENS = 2_000;
const SAFETY_MARGIN = 0.95;

const OUTPUT_TOKEN_TARGETS: Record<AgentTask, number> = {
  scanner: 8_000,
  "threat-model": 4_000,
  "red-team": 16_000,
  "blue-team": 8_000,
  judge: 4_000,
  patch: 16_000,
  review: 4_000
};

function getModelLimits(model: string): ModelLimits {
  const limits = MODEL_LIMITS[model];
  if (limits) return limits;
  for (const [key, value] of Object.entries(MODEL_LIMITS)) {
    if (model.startsWith(key.split("-").slice(0, 3).join("-"))) {
      return value;
    }
  }
  return { contextWindow: 200_000, maxOutputTokens: 32_000 };
}

export function computeTokenBudget(model: string, task: AgentTask): TokenBudget {
  const limits = getModelLimits(model);
  const outputTarget = OUTPUT_TOKEN_TARGETS[task];
  const maxOutput = Math.min(outputTarget, limits.maxOutputTokens);
  const usableContext = Math.floor(limits.contextWindow * SAFETY_MARGIN);
  const maxInput = usableContext - maxOutput - SYSTEM_PROMPT_RESERVE_TOKENS;

  return {
    model,
    maxInputTokens: Math.max(maxInput, 1_000),
    maxOutputTokens: maxOutput,
    reservedForSystem: SYSTEM_PROMPT_RESERVE_TOKENS
  };
}

/**
 * Rough character-based token estimate.
 * ~4 characters per token for English/code, conservative for safety.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 3.5);
}

export interface TruncationResult {
  text: string;
  truncated: boolean;
  originalTokens: number;
  finalTokens: number;
}

export function truncateToTokenBudget(text: string, maxTokens: number): TruncationResult {
  const originalTokens = estimateTokens(text);
  if (originalTokens <= maxTokens) {
    return { text, truncated: false, originalTokens, finalTokens: originalTokens };
  }

  const maxChars = Math.floor(maxTokens * 3.5);
  const lines = text.split("\n");
  let charCount = 0;
  let cutLine = lines.length;

  for (let i = 0; i < lines.length; i++) {
    charCount += lines[i].length + 1;
    if (charCount > maxChars) {
      cutLine = i;
      break;
    }
  }

  const truncated = lines.slice(0, cutLine).join("\n");
  const suffix = `\n\n[... truncated: ${originalTokens - estimateTokens(truncated)} tokens omitted]`;
  const result = truncated + suffix;

  return {
    text: result,
    truncated: true,
    originalTokens,
    finalTokens: estimateTokens(result)
  };
}
