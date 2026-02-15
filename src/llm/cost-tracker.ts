/**
 * Cost Tracker & Model Optimizer
 *
 * Tracks per-request token usage and cost, provides cost analysis per agent task,
 * and supports dynamic model routing based on task complexity.
 */

import type { AgentTask } from "./router";

// Pricing per million tokens (as of Feb 2026)
const PRICING: Record<string, { input: number; output: number }> = {
  "claude-opus-4-6-20250605": { input: 15.0, output: 75.0 },
  "claude-sonnet-4-5-20250929": { input: 3.0, output: 15.0 },
  "claude-haiku-4-5-20251001": { input: 0.80, output: 4.0 }
};

export interface CostRecord {
  request_id: string;
  model: string;
  task: AgentTask;
  input_tokens: number;
  output_tokens: number;
  input_cost_usd: number;
  output_cost_usd: number;
  total_cost_usd: number;
  latency_ms: number;
  timestamp: string;
}

export interface TaskCostSummary {
  task: AgentTask;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_cost_usd: number;
  avg_cost_per_request_usd: number;
  avg_latency_ms: number;
  model_breakdown: Record<string, { requests: number; cost_usd: number }>;
}

export interface CostReport {
  generated_at: string;
  total_cost_usd: number;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  by_task: TaskCostSummary[];
  by_model: Record<string, { requests: number; cost_usd: number; avg_latency_ms: number }>;
  recommendations: string[];
}

function computeCost(model: string, inputTokens: number, outputTokens: number): { input: number; output: number; total: number } {
  const pricing = PRICING[model];
  if (!pricing) {
    // Fallback to Sonnet pricing for unknown models
    const fallback = PRICING["claude-sonnet-4-5-20250929"];
    const input = (inputTokens / 1_000_000) * fallback.input;
    const output = (outputTokens / 1_000_000) * fallback.output;
    return { input, output, total: input + output };
  }

  const input = (inputTokens / 1_000_000) * pricing.input;
  const output = (outputTokens / 1_000_000) * pricing.output;
  return { input, output, total: input + output };
}

export class CostTracker {
  private records: CostRecord[] = [];
  private maxRecords: number;

  constructor(maxRecords = 10_000) {
    this.maxRecords = maxRecords;
  }

  record(
    requestId: string,
    model: string,
    task: AgentTask,
    inputTokens: number,
    outputTokens: number,
    latencyMs: number
  ): CostRecord {
    const cost = computeCost(model, inputTokens, outputTokens);

    const entry: CostRecord = {
      request_id: requestId,
      model,
      task,
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      input_cost_usd: Math.round(cost.input * 1_000_000) / 1_000_000,
      output_cost_usd: Math.round(cost.output * 1_000_000) / 1_000_000,
      total_cost_usd: Math.round(cost.total * 1_000_000) / 1_000_000,
      latency_ms: latencyMs,
      timestamp: new Date().toISOString()
    };

    this.records.push(entry);
    this.trimRecords();

    return entry;
  }

  getRecords(): CostRecord[] {
    return [...this.records];
  }

  getTotalCost(): number {
    return this.records.reduce((sum, r) => sum + r.total_cost_usd, 0);
  }

  generateReport(): CostReport {
    const byTask = new Map<AgentTask, CostRecord[]>();
    const byModel = new Map<string, CostRecord[]>();

    for (const record of this.records) {
      if (!byTask.has(record.task)) byTask.set(record.task, []);
      byTask.get(record.task)!.push(record);

      if (!byModel.has(record.model)) byModel.set(record.model, []);
      byModel.get(record.model)!.push(record);
    }

    const taskSummaries: TaskCostSummary[] = [];
    for (const [task, records] of byTask) {
      const modelBreakdown: Record<string, { requests: number; cost_usd: number }> = {};
      for (const r of records) {
        if (!modelBreakdown[r.model]) modelBreakdown[r.model] = { requests: 0, cost_usd: 0 };
        modelBreakdown[r.model].requests++;
        modelBreakdown[r.model].cost_usd += r.total_cost_usd;
      }

      taskSummaries.push({
        task,
        total_requests: records.length,
        total_input_tokens: records.reduce((s, r) => s + r.input_tokens, 0),
        total_output_tokens: records.reduce((s, r) => s + r.output_tokens, 0),
        total_cost_usd: records.reduce((s, r) => s + r.total_cost_usd, 0),
        avg_cost_per_request_usd: records.reduce((s, r) => s + r.total_cost_usd, 0) / records.length,
        avg_latency_ms: Math.round(records.reduce((s, r) => s + r.latency_ms, 0) / records.length),
        model_breakdown: modelBreakdown
      });
    }

    const modelSummary: Record<string, { requests: number; cost_usd: number; avg_latency_ms: number }> = {};
    for (const [model, records] of byModel) {
      modelSummary[model] = {
        requests: records.length,
        cost_usd: records.reduce((s, r) => s + r.total_cost_usd, 0),
        avg_latency_ms: Math.round(records.reduce((s, r) => s + r.latency_ms, 0) / records.length)
      };
    }

    const recommendations = this.generateRecommendations(taskSummaries, modelSummary);

    return {
      generated_at: new Date().toISOString(),
      total_cost_usd: this.getTotalCost(),
      total_requests: this.records.length,
      total_input_tokens: this.records.reduce((s, r) => s + r.input_tokens, 0),
      total_output_tokens: this.records.reduce((s, r) => s + r.output_tokens, 0),
      by_task: taskSummaries,
      by_model: modelSummary,
      recommendations
    };
  }

  reset(): void {
    this.records = [];
  }

  private trimRecords(): void {
    if (this.records.length > this.maxRecords) {
      this.records = this.records.slice(-this.maxRecords);
    }
  }

  private generateRecommendations(
    taskSummaries: TaskCostSummary[],
    modelSummary: Record<string, { requests: number; cost_usd: number; avg_latency_ms: number }>
  ): string[] {
    const recommendations: string[] = [];

    // Check if Opus is being used for tasks that could use cheaper models
    for (const summary of taskSummaries) {
      const opusKey = "claude-opus-4-6-20250605";
      const opusBreakdown = summary.model_breakdown[opusKey];
      if (opusBreakdown && (summary.task === "scanner" || summary.task === "review")) {
        const potentialSavings = opusBreakdown.cost_usd * 0.8; // ~80% cheaper with Haiku
        if (potentialSavings > 0.01) {
          recommendations.push(
            `Task '${summary.task}' is using Opus ($${opusBreakdown.cost_usd.toFixed(4)}). ` +
            `Consider downgrading to Haiku for ~$${potentialSavings.toFixed(4)} savings.`
          );
        }
      }
    }

    // Check if overall cost is dominated by a single task
    const totalCost = taskSummaries.reduce((s, t) => s + t.total_cost_usd, 0);
    for (const summary of taskSummaries) {
      const ratio = totalCost > 0 ? summary.total_cost_usd / totalCost : 0;
      if (ratio > 0.5 && summary.total_requests > 5) {
        recommendations.push(
          `Task '${summary.task}' accounts for ${(ratio * 100).toFixed(0)}% of total cost. ` +
          `Review if prompt length or output target can be reduced.`
        );
      }
    }

    // Check Opus latency for non-critical tasks
    const opusStats = modelSummary["claude-opus-4-6-20250605"];
    if (opusStats && opusStats.avg_latency_ms > 15_000) {
      recommendations.push(
        `Opus average latency is ${opusStats.avg_latency_ms}ms. ` +
        `Consider using Sonnet for time-sensitive tasks (red-team, blue-team).`
      );
    }

    if (recommendations.length === 0) {
      recommendations.push("No optimization recommendations at this time. Model selection looks efficient.");
    }

    return recommendations;
  }
}

// Complexity-based model routing

export type TaskComplexity = "low" | "medium" | "high";

export function assessComplexity(
  codeLength: number,
  fileCount: number,
  vulnClassCount: number
): TaskComplexity {
  // Low: small files, single vuln class
  if (codeLength < 5_000 && fileCount <= 2 && vulnClassCount <= 1) return "low";
  // High: large codebases, many vuln classes
  if (codeLength > 50_000 || fileCount > 10 || vulnClassCount > 3) return "high";
  return "medium";
}

const COMPLEXITY_MODEL_OVERRIDES: Record<TaskComplexity, Partial<Record<AgentTask, string>>> = {
  low: {
    scanner: "claude-haiku-4-5-20251001",
    "red-team": "claude-haiku-4-5-20251001",
    "blue-team": "claude-haiku-4-5-20251001",
    judge: "claude-sonnet-4-5-20250929"
  },
  medium: {
    // Use defaults from router.ts
  },
  high: {
    scanner: "claude-sonnet-4-5-20250929",
    "red-team": "claude-opus-4-6-20250605",
    judge: "claude-opus-4-6-20250605"
  }
};

export function getComplexityAdjustedModel(task: AgentTask, defaultModel: string, complexity: TaskComplexity): string {
  return COMPLEXITY_MODEL_OVERRIDES[complexity]?.[task] ?? defaultModel;
}

// Singleton tracker
let defaultTracker: CostTracker | undefined;

export function getDefaultTracker(): CostTracker {
  if (!defaultTracker) {
    defaultTracker = new CostTracker();
  }
  return defaultTracker;
}
