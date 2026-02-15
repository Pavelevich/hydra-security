import { promises as fs } from "node:fs";
import path from "node:path";
import { runFullScan } from "../../src/orchestrator/run-scan";
import type { DatasetManifest, EvalReport, Finding, RepoScore, SystemScore } from "../../src/types";
import { runSingleAgentBaseline } from "../baseline/single-agent-baseline";

function getArg(flag: string): string | undefined {
  const idx = process.argv.findIndex((arg: string) => arg === flag);
  return idx >= 0 ? process.argv[idx + 1] : undefined;
}

function findingKey(vulnClass: string, relFile: string, line: number): string {
  return `${vulnClass}|${relFile}|${line}`;
}

function normalizeRel(rootPath: string, absoluteOrRelativePath: string): string {
  const abs = path.isAbsolute(absoluteOrRelativePath)
    ? absoluteOrRelativePath
    : path.join(rootPath, absoluteOrRelativePath);
  return path.relative(rootPath, abs).replaceAll("\\", "/");
}

function scoreRepo(
  repoId: string,
  rootPath: string,
  expected: Array<{ vuln_class: string; file: string; line: number }>,
  predicted: Finding[]
): RepoScore {
  const expectedSet = new Set(
    expected.map((item) => findingKey(item.vuln_class, normalizeRel(rootPath, item.file), item.line))
  );
  const predictedSet = new Set(
    predicted.map((item) => findingKey(item.vuln_class, normalizeRel(rootPath, item.file), item.line))
  );

  let tp = 0;
  for (const k of predictedSet) {
    if (expectedSet.has(k)) {
      tp += 1;
    }
  }
  const fp = predictedSet.size - tp;
  const fn = expectedSet.size - tp;
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);

  return { repo_id: repoId, tp, fp, fn, precision, recall };
}

function finalizeSystem(systemId: string, repos: RepoScore[]): SystemScore {
  const tp = repos.reduce((acc, v) => acc + v.tp, 0);
  const fp = repos.reduce((acc, v) => acc + v.fp, 0);
  const fn = repos.reduce((acc, v) => acc + v.fn, 0);
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);

  return {
    system_id: systemId,
    repos,
    totals: { tp, fp, fn, precision, recall }
  };
}

async function main(): Promise<void> {
  const manifestArg =
    getArg("--manifest") ?? "evaluation/datasets/manifests/d1-solana-seeded-v1.json";
  const manifestPath = path.resolve(process.cwd(), manifestArg);
  const manifestRaw = await fs.readFile(manifestPath, "utf8");
  const manifest = JSON.parse(manifestRaw) as DatasetManifest;

  const hydraRepoScores: RepoScore[] = [];
  const baselineRepoScores: RepoScore[] = [];

  for (const repo of manifest.repos) {
    const repoRoot = path.resolve(process.cwd(), repo.path);
    const hydraScan = await runFullScan(repoRoot);
    const baselineFindings = await runSingleAgentBaseline(repoRoot);

    hydraRepoScores.push(
      scoreRepo(repo.id, repoRoot, repo.expected_findings, hydraScan.findings)
    );
    baselineRepoScores.push(
      scoreRepo(repo.id, repoRoot, repo.expected_findings, baselineFindings)
    );
  }

  const report: EvalReport = {
    generated_at: new Date().toISOString(),
    dataset_id: manifest.dataset_id,
    systems: [
      finalizeSystem("hydra-swarm-v1", hydraRepoScores),
      finalizeSystem("baseline-single-agent", baselineRepoScores)
    ],
    notes: [
      "This is a scaffold runner with seeded datasets.",
      "Use this pipeline to integrate real scanners, adjudication, and confidence intervals."
    ]
  };

  const outDir = path.resolve(process.cwd(), "evaluation/reports");
  await fs.mkdir(outDir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const outPath = path.join(outDir, `eval-${manifest.dataset_id}-${ts}.json`);
  await fs.writeFile(outPath, JSON.stringify(report, null, 2), "utf8");

  console.log(`Evaluation completed for dataset: ${manifest.dataset_id}`);
  for (const system of report.systems) {
    console.log(
      `${system.system_id}: precision=${system.totals.precision.toFixed(3)} recall=${system.totals.recall.toFixed(3)} (tp=${system.totals.tp}, fp=${system.totals.fp}, fn=${system.totals.fn})`
    );
  }
  console.log(`Report written: ${outPath}`);
}

main().catch((error) => {
  console.error("Evaluation runner failed:", error);
  process.exitCode = 1;
});
