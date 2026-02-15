import { promises as fs } from "node:fs";
import type { AdversarialResult, Finding } from "../types";
import { runRedTeamAgent } from "../agents/red-team/agent";
import { runBlueTeamAgent } from "../agents/blue-team/agent";
import { runJudgeAgent } from "../agents/judge/agent";

export interface AdversarialPipelineOptions {
  maxConcurrent?: number;
  skipSandbox?: boolean;
  minConfidenceForAdversarial?: number;
}

const DEFAULT_MAX_CONCURRENT = 2;
const DEFAULT_MIN_CONFIDENCE = 50;

async function readSource(filePath: string): Promise<string> {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return "";
  }
}

async function processOneFinding(finding: Finding): Promise<AdversarialResult> {
  const sourceCode = await readSource(finding.file);

  const redTeam = await runRedTeamAgent({
    finding,
    sourceCode
  });

  const blueTeam = await runBlueTeamAgent({
    finding,
    redTeamAssessment: redTeam,
    sourceCode
  });

  const judge = await runJudgeAgent({
    finding,
    redTeamAssessment: redTeam,
    blueTeamAssessment: blueTeam
  });

  return { finding, red_team: redTeam, blue_team: blueTeam, judge };
}

export async function runAdversarialPipeline(
  findings: Finding[],
  options: AdversarialPipelineOptions = {}
): Promise<AdversarialResult[]> {
  const maxConcurrent = options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
  const minConfidence = options.minConfidenceForAdversarial ?? DEFAULT_MIN_CONFIDENCE;

  const eligible = findings.filter((f) => f.confidence >= minConfidence);

  if (eligible.length === 0) {
    return [];
  }

  const results: AdversarialResult[] = [];
  const queue = [...eligible];
  const running = new Set<Promise<void>>();

  const processNext = (): void => {
    const finding = queue.shift();
    if (!finding) return;

    let taskPromise: Promise<void>;
    taskPromise = processOneFinding(finding)
      .then((result) => {
        results.push(result);
      })
      .catch((error) => {
        results.push({
          finding,
          red_team: {
            exploitable: false,
            attack_steps: [],
            confidence: 0,
            reason: `Adversarial pipeline error: ${error instanceof Error ? error.message : String(error)}`,
            sandbox_executed: false
          }
        });
      })
      .finally(() => {
        running.delete(taskPromise);
      });

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

export function filterByVerdict(results: AdversarialResult[]): Finding[] {
  return results
    .filter((r) => {
      if (!r.judge) return true;
      return r.judge.verdict === "confirmed" || r.judge.verdict === "likely";
    })
    .map((r) => {
      if (!r.judge) return r.finding;
      return {
        ...r.finding,
        severity: r.judge.final_severity,
        confidence: r.judge.final_confidence
      };
    });
}
