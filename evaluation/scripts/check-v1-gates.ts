import { promises as fs } from "node:fs";
import path from "node:path";
import type { EvalReport, ScoreTotals, SystemScore } from "../../src/types";

const DATASETS = {
  d1: "d1-solana-seeded-v1",
  d2: "d2-solana-seeded-v2",
  d3: "d3-solana-clean-controls-v1",
  d4: "d4-solana-holdout-v1"
} as const;

const RELATIVE_GAIN_TARGET = 0.1;
const SATURATION_FLOOR = 0.99;

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function findLatestReportName(files: string[], datasetId: string): string | undefined {
  const prefix = `eval-${datasetId}-`;
  const matches = files.filter((name) => name.startsWith(prefix) && name.endsWith(".json"));
  if (matches.length === 0) {
    return undefined;
  }
  return matches.sort().at(-1);
}

function getSystem(report: EvalReport, systemId: string): SystemScore {
  const system = report.systems.find((entry) => entry.system_id === systemId);
  if (!system) {
    throw new Error(`System ${systemId} not found in ${report.dataset_id}`);
  }
  return system;
}

function combineTotals(totals: ScoreTotals[]): ScoreTotals {
  const tp = totals.reduce((acc, t) => acc + t.tp, 0);
  const fp = totals.reduce((acc, t) => acc + t.fp, 0);
  const fn = totals.reduce((acc, t) => acc + t.fn, 0);
  const cleanRepoCount = totals.reduce((acc, t) => acc + t.clean_repo_count, 0);
  const cleanRepoFpCount = totals.reduce((acc, t) => acc + t.clean_repo_fp_count, 0);

  return {
    tp,
    fp,
    fn,
    precision: tp + fp === 0 ? 1 : tp / (tp + fp),
    recall: tp + fn === 0 ? 1 : tp / (tp + fn),
    clean_repo_count: cleanRepoCount,
    clean_repo_fp_count: cleanRepoFpCount,
    clean_repo_fp_rate: cleanRepoCount === 0 ? 0 : cleanRepoFpCount / cleanRepoCount
  };
}

function relativeGain(current: number, baseline: number): number {
  if (baseline === 0) {
    return current > 0 ? 1 : 0;
  }
  return (current - baseline) / baseline;
}

async function main(): Promise<void> {
  const reportsDir = path.resolve(process.cwd(), "evaluation/reports");
  const reportFiles = await fs.readdir(reportsDir);

  const latestByDataset = new Map<string, EvalReport>();
  for (const datasetId of Object.values(DATASETS)) {
    const latestName = findLatestReportName(reportFiles, datasetId);
    if (!latestName) {
      throw new Error(`Missing report for dataset ${datasetId}. Run bun run eval:phase0 first.`);
    }
    const reportPath = path.join(reportsDir, latestName);
    const reportRaw = await fs.readFile(reportPath, "utf8");
    latestByDataset.set(datasetId, JSON.parse(reportRaw) as EvalReport);
  }

  const hydraD1 = getSystem(latestByDataset.get(DATASETS.d1)!, "hydra-swarm-v1").totals;
  const hydraD2 = getSystem(latestByDataset.get(DATASETS.d2)!, "hydra-swarm-v1").totals;
  const hydraD3 = getSystem(latestByDataset.get(DATASETS.d3)!, "hydra-swarm-v1").totals;
  const hydraD4 = getSystem(latestByDataset.get(DATASETS.d4)!, "hydra-swarm-v1").totals;

  const singleD1 = getSystem(latestByDataset.get(DATASETS.d1)!, "baseline-single-agent").totals;
  const singleD2 = getSystem(latestByDataset.get(DATASETS.d2)!, "baseline-single-agent").totals;

  const hydraD1D2 = combineTotals([hydraD1, hydraD2]);
  const hydraD1D2D3 = combineTotals([hydraD1, hydraD2, hydraD3]);
  const singleD1D2 = combineTotals([singleD1, singleD2]);

  const v1RecallGate = hydraD1D2.recall >= 0.85;
  const v1PrecisionGate = hydraD1D2D3.precision >= 0.8;
  const strongRecallRelativeGain = relativeGain(hydraD1D2.recall, singleD1D2.recall);
  const strongPrecisionRelativeGain = relativeGain(hydraD1D2.precision, singleD1D2.precision);
  const precisionSaturated = singleD1D2.precision >= SATURATION_FLOOR;
  const precisionComparisonPass = precisionSaturated
    ? hydraD1D2.precision >= singleD1D2.precision
    : strongPrecisionRelativeGain >= RELATIVE_GAIN_TARGET;
  const strongerThanBaselineGate =
    strongRecallRelativeGain >= RELATIVE_GAIN_TARGET && precisionComparisonPass;

  console.log("V1 Gate Check");
  console.log("");
  console.log(`Hydra D1+D2 recall: ${fmtPct(hydraD1D2.recall)} (${v1RecallGate ? "PASS" : "FAIL"})`);
  console.log(
    `Hydra D1+D2+D3 precision: ${fmtPct(hydraD1D2D3.precision)} (${v1PrecisionGate ? "PASS" : "FAIL"})`
  );
  console.log(
    `Hydra clean control FP rate (D3): ${fmtPct(hydraD3.clean_repo_fp_rate)} (target: as low as possible)`
  );
  console.log(
    `Hydra holdout recall (D4): ${fmtPct(hydraD4.recall)} (informational, not a V1 hard gate)`
  );
  console.log("");
  console.log("Stronger Than Baseline Gate (D1+D2)");
  console.log(`Recall relative gain vs single-agent: ${fmtPct(strongRecallRelativeGain)}`);
  if (precisionSaturated) {
    console.log(
      `Precision baseline saturation mode: baseline=${fmtPct(singleD1D2.precision)} (>= ${fmtPct(SATURATION_FLOOR)})`
    );
    console.log(
      `Precision non-regression vs single-agent: ${hydraD1D2.precision >= singleD1D2.precision ? "PASS" : "FAIL"}`
    );
  } else {
    console.log(`Precision relative gain vs single-agent: ${fmtPct(strongPrecisionRelativeGain)}`);
  }
  console.log(`Overall stronger-than-baseline gate: ${strongerThanBaselineGate ? "PASS" : "FAIL"}`);
  console.log("");
  console.log("Not evaluated by this script:");
  console.log("- Exploit Confirmation Precision (needs adversarial sandbox loop)");
  console.log("- Patch Acceptance Rate (needs patch/review loop)");
  console.log("- Median full scan time gate (needs timing telemetry and reference corpus)");
}

main().catch((error) => {
  console.error("V1 gate check failed:", error);
  process.exitCode = 1;
});
