/**
 * A/B Prompt Testing Framework
 *
 * Manages prompt variants per agent task, runs comparative evaluations,
 * and tracks recall/precision across variants to select the best-performing prompts.
 */

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { AgentTask } from "./router";

export interface PromptVariant {
  id: string;
  task: AgentTask;
  name: string;
  system: string;
  userTemplate: string;
  variables: string[];
  created_at: string;
  metadata?: Record<string, string>;
}

export interface VariantResult {
  variant_id: string;
  repo_id: string;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  latency_ms: number;
  token_cost: number;
  timestamp: string;
}

export interface VariantSummary {
  variant_id: string;
  variant_name: string;
  task: AgentTask;
  runs: number;
  avg_precision: number;
  avg_recall: number;
  avg_f1: number;
  avg_latency_ms: number;
  avg_token_cost: number;
  best_f1: number;
  worst_f1: number;
}

export interface ABTestReport {
  task: AgentTask;
  generated_at: string;
  variants: VariantSummary[];
  winner_id: string;
  winner_name: string;
  margin: number;
}

const STORE_DIR = path.resolve(".hydra/prompt-variants");

function variantHash(variant: PromptVariant): string {
  const content = `${variant.task}:${variant.system}:${variant.userTemplate}`;
  return createHash("sha256").update(content).digest("hex").slice(0, 12);
}

function computeF1(precision: number, recall: number): number {
  if (precision + recall === 0) return 0;
  return (2 * precision * recall) / (precision + recall);
}

export function createVariant(
  task: AgentTask,
  name: string,
  system: string,
  userTemplate: string,
  variables: string[],
  metadata?: Record<string, string>
): PromptVariant {
  const variant: PromptVariant = {
    id: "",
    task,
    name,
    system,
    userTemplate,
    variables,
    created_at: new Date().toISOString(),
    metadata
  };
  variant.id = variantHash(variant);
  return variant;
}

export function recordResult(
  variantId: string,
  repoId: string,
  tp: number,
  fp: number,
  fn: number,
  latencyMs: number,
  tokenCost: number
): VariantResult {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 1;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 1;

  return {
    variant_id: variantId,
    repo_id: repoId,
    tp,
    fp,
    fn,
    precision,
    recall,
    f1: computeF1(precision, recall),
    latency_ms: latencyMs,
    token_cost: tokenCost,
    timestamp: new Date().toISOString()
  };
}

export function summarizeVariant(variant: PromptVariant, results: VariantResult[]): VariantSummary {
  const variantResults = results.filter((r) => r.variant_id === variant.id);

  if (variantResults.length === 0) {
    return {
      variant_id: variant.id,
      variant_name: variant.name,
      task: variant.task,
      runs: 0,
      avg_precision: 0,
      avg_recall: 0,
      avg_f1: 0,
      avg_latency_ms: 0,
      avg_token_cost: 0,
      best_f1: 0,
      worst_f1: 0
    };
  }

  const n = variantResults.length;
  const avgPrecision = variantResults.reduce((s, r) => s + r.precision, 0) / n;
  const avgRecall = variantResults.reduce((s, r) => s + r.recall, 0) / n;
  const avgF1 = variantResults.reduce((s, r) => s + r.f1, 0) / n;
  const avgLatency = variantResults.reduce((s, r) => s + r.latency_ms, 0) / n;
  const avgCost = variantResults.reduce((s, r) => s + r.token_cost, 0) / n;
  const f1s = variantResults.map((r) => r.f1);

  return {
    variant_id: variant.id,
    variant_name: variant.name,
    task: variant.task,
    runs: n,
    avg_precision: avgPrecision,
    avg_recall: avgRecall,
    avg_f1: avgF1,
    avg_latency_ms: Math.round(avgLatency),
    avg_token_cost: Math.round(avgCost * 100) / 100,
    best_f1: Math.max(...f1s),
    worst_f1: Math.min(...f1s)
  };
}

export function selectWinner(summaries: VariantSummary[]): { winner: VariantSummary; margin: number } {
  const sorted = [...summaries]
    .filter((s) => s.runs > 0)
    .sort((a, b) => {
      // Primary: avg F1 score
      const f1Diff = b.avg_f1 - a.avg_f1;
      if (Math.abs(f1Diff) > 0.01) return f1Diff;
      // Tiebreaker: lower cost
      return a.avg_token_cost - b.avg_token_cost;
    });

  if (sorted.length === 0) {
    throw new Error("No variants with results to compare");
  }

  const winner = sorted[0];
  const runnerUp = sorted[1];
  const margin = runnerUp ? winner.avg_f1 - runnerUp.avg_f1 : 1;

  return { winner, margin };
}

export function generateABTestReport(
  task: AgentTask,
  variants: PromptVariant[],
  results: VariantResult[]
): ABTestReport {
  const summaries = variants
    .filter((v) => v.task === task)
    .map((v) => summarizeVariant(v, results));

  const { winner, margin } = selectWinner(summaries);

  return {
    task,
    generated_at: new Date().toISOString(),
    variants: summaries,
    winner_id: winner.variant_id,
    winner_name: winner.variant_name,
    margin
  };
}

// Persistence

export async function saveVariants(variants: PromptVariant[]): Promise<void> {
  await fs.mkdir(STORE_DIR, { recursive: true });
  const filePath = path.join(STORE_DIR, "variants.json");
  await fs.writeFile(filePath, JSON.stringify(variants, null, 2), "utf8");
}

export async function loadVariants(): Promise<PromptVariant[]> {
  const filePath = path.join(STORE_DIR, "variants.json");
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as PromptVariant[];
  } catch {
    return [];
  }
}

export async function saveResults(results: VariantResult[]): Promise<void> {
  await fs.mkdir(STORE_DIR, { recursive: true });
  const filePath = path.join(STORE_DIR, "results.json");
  await fs.writeFile(filePath, JSON.stringify(results, null, 2), "utf8");
}

export async function loadResults(): Promise<VariantResult[]> {
  const filePath = path.join(STORE_DIR, "results.json");
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as VariantResult[];
  } catch {
    return [];
  }
}

export async function saveReport(report: ABTestReport): Promise<void> {
  await fs.mkdir(STORE_DIR, { recursive: true });
  const filePath = path.join(STORE_DIR, `ab-report-${report.task}-${Date.now()}.json`);
  await fs.writeFile(filePath, JSON.stringify(report, null, 2), "utf8");
}
