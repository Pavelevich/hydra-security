import { randomUUID } from "node:crypto";
import type { AgentRunRecord, Finding, ScanTarget } from "../types";
import { solanaAccountValidationScanner } from "../agents/scanner/solana-account-validation";
import { solanaCpiScanner } from "../agents/scanner/solana-cpi";
import { solanaPdaScanner } from "../agents/scanner/solana-pda";
import { runDeterministicSignalAdapters } from "../agents/scanner/deterministic-signals";
import { runLlmScanner, LLM_SCANNER_CONFIGS } from "../agents/scanner/llm-scanner";

const scanners = [solanaAccountValidationScanner, solanaCpiScanner, solanaPdaScanner];
const DEFAULT_MAX_CONCURRENT_AGENTS = 3;
const DEFAULT_AGENT_TIMEOUT_MS = 90_000;
const LLM_AGENT_TIMEOUT_MS = 300_000;

export interface DispatchResult {
  findings: Finding[];
  agent_runs: AgentRunRecord[];
}

class AgentTimeoutError extends Error {
  constructor(agentId: string, timeoutMs: number) {
    super(`Agent timed out: ${agentId} (${timeoutMs}ms)`);
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function readPositiveIntFromEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

async function withTimeout<T>(fn: () => Promise<T>, timeoutMs: number, agentId: string): Promise<T> {
  let timeoutHandle: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(new AgentTimeoutError(agentId, timeoutMs));
    }, timeoutMs);
  });

  try {
    return await Promise.race([fn(), timeoutPromise]);
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
}

interface AgentTask {
  agent_id: string;
  execute: () => Promise<Finding[]>;
  timeoutMs?: number;
}

function buildTasks(target: ScanTarget): AgentTask[] {
  const scannerTasks: AgentTask[] = scanners.map((scanner) => ({
    agent_id: scanner.id,
    execute: () => scanner.scan(target.root_path)
  }));

  const tasks: AgentTask[] = [
    ...scannerTasks,
    {
      agent_id: "signal.deterministic.adapters",
      execute: () => runDeterministicSignalAdapters(target.root_path)
    }
  ];

  // Wire LLM-powered scanners when ANTHROPIC_API_KEY is available
  if (process.env.ANTHROPIC_API_KEY) {
    for (const config of LLM_SCANNER_CONFIGS) {
      tasks.push({
        agent_id: config.scannerId,
        execute: () => runLlmScanner(target.root_path, {
          vulnFocus: config.vulnFocus,
          scannerId: config.scannerId
        }),
        timeoutMs: LLM_AGENT_TIMEOUT_MS
      });
    }
  }

  return tasks;
}

export async function dispatchScanners(target: ScanTarget): Promise<DispatchResult> {
  const maxConcurrentAgents = readPositiveIntFromEnv(
    "HYDRA_MAX_CONCURRENT_AGENTS",
    DEFAULT_MAX_CONCURRENT_AGENTS
  );
  const agentTimeoutMs = readPositiveIntFromEnv("HYDRA_AGENT_TIMEOUT_MS", DEFAULT_AGENT_TIMEOUT_MS);
  const tasks = buildTasks(target);
  const records: AgentRunRecord[] = tasks.map((task) => ({
    id: randomUUID(),
    agent_id: task.agent_id,
    status: "queued",
    queued_at: nowIso()
  }));
  const queue = tasks.map((_, index) => index);
  const running = new Set<Promise<void>>();
  const findings: Finding[] = [];

  const runTask = (index: number): void => {
    const task = tasks[index];
    const record = records[index];
    let taskPromise: Promise<void>;
    taskPromise = (async () => {
      record.status = "running";
      record.started_at = nowIso();
      const startedAtMs = Date.now();

      try {
        const taskFindings = await withTimeout(task.execute, task.timeoutMs ?? agentTimeoutMs, task.agent_id);
        record.status = "completed";
        record.finding_count = taskFindings.length;
        findings.push(...taskFindings);
      } catch (error) {
        if (error instanceof AgentTimeoutError) {
          record.status = "timed_out";
        } else {
          record.status = "failed";
        }
        record.error = error instanceof Error ? error.message : "Unknown agent error";
      } finally {
        record.completed_at = nowIso();
        record.duration_ms = Date.now() - startedAtMs;
      }
    })().finally(() => {
      running.delete(taskPromise);
    });
    running.add(taskPromise);
  };

  while (queue.length > 0 || running.size > 0) {
    while (queue.length > 0 && running.size < maxConcurrentAgents) {
      runTask(queue.shift() as number);
    }
    if (running.size > 0) {
      await Promise.race(running);
    }
  }

  return { findings, agent_runs: records };
}
