import { promises as fs } from "node:fs";
import path from "node:path";
import type { DatasetManifest, Finding } from "../../src/types";
import { runAllLlmScanners } from "../../src/agents/scanner/llm-scanner";

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

interface TuneResult {
  repo_id: string;
  expected: number;
  predicted: number;
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  findings: Array<{ vuln_class: string; file: string; line: number; confidence: number }>;
}

async function main(): Promise<void> {
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error("ANTHROPIC_API_KEY must be set to run prompt tuning.");
    process.exitCode = 1;
    return;
  }

  const manifestArg =
    getArg("--manifest") ?? "evaluation/datasets/manifests/d1-solana-seeded-v1.json";
  const manifestPath = path.resolve(process.cwd(), manifestArg);
  const manifestRaw = await fs.readFile(manifestPath, "utf8");
  const manifest = JSON.parse(manifestRaw) as DatasetManifest;

  console.log(`Prompt tuning evaluation for dataset: ${manifest.dataset_id}`);
  console.log(`Repos: ${manifest.repos.length}`);
  console.log("");

  const results: TuneResult[] = [];

  for (const repo of manifest.repos) {
    const repoRoot = path.resolve(process.cwd(), repo.path);
    console.log(`Scanning ${repo.id} at ${repoRoot}...`);

    const findings = await runAllLlmScanners(repoRoot);

    const expectedSet = new Set(
      repo.expected_findings.map((item) =>
        findingKey(item.vuln_class, normalizeRel(repoRoot, item.file), item.line)
      )
    );
    const predictedSet = new Set(
      findings.map((item: Finding) =>
        findingKey(item.vuln_class, normalizeRel(repoRoot, item.file), item.line)
      )
    );

    let tp = 0;
    for (const k of predictedSet) {
      if (expectedSet.has(k)) tp += 1;
    }
    const fp = predictedSet.size - tp;
    const fn = expectedSet.size - tp;

    const result: TuneResult = {
      repo_id: repo.id,
      expected: expectedSet.size,
      predicted: predictedSet.size,
      tp,
      fp,
      fn,
      precision: tp + fp === 0 ? 1 : tp / (tp + fp),
      recall: tp + fn === 0 ? 1 : tp / (tp + fn),
      findings: findings.map((f: Finding) => ({
        vuln_class: f.vuln_class,
        file: normalizeRel(repoRoot, f.file),
        line: f.line,
        confidence: f.confidence
      }))
    };

    results.push(result);

    console.log(
      `  ${repo.id}: precision=${result.precision.toFixed(3)} recall=${result.recall.toFixed(3)} (tp=${tp}, fp=${fp}, fn=${fn})`
    );
  }

  const totalTp = results.reduce((a, r) => a + r.tp, 0);
  const totalFp = results.reduce((a, r) => a + r.fp, 0);
  const totalFn = results.reduce((a, r) => a + r.fn, 0);
  const totalPrecision = totalTp + totalFp === 0 ? 1 : totalTp / (totalTp + totalFp);
  const totalRecall = totalTp + totalFn === 0 ? 1 : totalTp / (totalTp + totalFn);

  console.log("");
  console.log("=== Aggregate ===");
  console.log(
    `precision=${totalPrecision.toFixed(3)} recall=${totalRecall.toFixed(3)} (tp=${totalTp}, fp=${totalFp}, fn=${totalFn})`
  );

  const outDir = path.resolve(process.cwd(), "evaluation/reports");
  await fs.mkdir(outDir, { recursive: true });
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const outPath = path.join(outDir, `tune-${manifest.dataset_id}-${ts}.json`);
  await fs.writeFile(
    outPath,
    JSON.stringify(
      {
        generated_at: new Date().toISOString(),
        dataset_id: manifest.dataset_id,
        aggregate: { tp: totalTp, fp: totalFp, fn: totalFn, precision: totalPrecision, recall: totalRecall },
        repos: results
      },
      null,
      2
    ),
    "utf8"
  );

  console.log(`Report written: ${outPath}`);
}

main().catch((error) => {
  console.error("Prompt tuning failed:", error);
  process.exitCode = 1;
});
