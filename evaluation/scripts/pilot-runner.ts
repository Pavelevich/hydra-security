/**
 * Pilot Runner — runs Hydra Security scans against a list of real Solana/Anchor
 * repos and produces a benchmark report with aggregated metrics.
 *
 * Usage:
 *   bun run evaluation/scripts/pilot-runner.ts [--repos repos.json] [--output pilot-report.json]
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { runFullScan } from "../../src/orchestrator/run-scan";
import type { ScanResult } from "../../src/types";

interface PilotRepo {
  name: string;
  url: string;
  local_path?: string;
  branch?: string;
}

interface PilotConfig {
  repos: PilotRepo[];
}

interface RepoReport {
  repo: string;
  url: string;
  scan_result?: ScanResult;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  scan_duration_ms: number;
  error?: string;
}

interface PilotReport {
  generated_at: string;
  repos_scanned: number;
  repos_failed: number;
  total_findings: number;
  total_critical: number;
  total_high: number;
  avg_scan_duration_ms: number;
  repo_reports: RepoReport[];
}

function exec(cmd: string, args: string[], cwd?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd, timeout: 120_000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      const exitCode = error && "code" in error ? (error.code as number) ?? 1 : 0;
      resolve({ stdout: stdout ?? "", stderr: stderr ?? "", exitCode });
    });
  });
}

async function cloneOrUpdate(repo: PilotRepo, workDir: string): Promise<string> {
  const repoDir = path.join(workDir, repo.name);

  try {
    await fs.access(repoDir);
    // Already cloned — pull latest
    const branch = repo.branch ?? "main";
    await exec("git", ["fetch", "origin"], repoDir);
    await exec("git", ["checkout", branch], repoDir);
    await exec("git", ["pull", "--ff-only"], repoDir);
    return repoDir;
  } catch {
    // Not cloned yet
  }

  const cloneArgs = ["clone", "--depth", "1"];
  if (repo.branch) {
    cloneArgs.push("--branch", repo.branch);
  }
  cloneArgs.push(repo.url, repoDir);

  const result = await exec("git", cloneArgs);
  if (result.exitCode !== 0) {
    throw new Error(`Failed to clone ${repo.url}: ${result.stderr}`);
  }

  return repoDir;
}

async function scanRepo(repoPath: string): Promise<{ result: ScanResult; durationMs: number }> {
  const start = Date.now();
  const result = await runFullScan(repoPath);
  const durationMs = Date.now() - start;
  return { result, durationMs };
}

function getOptionValue(args: string[], flag: string): string | undefined {
  const idx = args.findIndex((arg) => arg === flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

// Default pilot repos (Solana/Anchor ecosystem — public repos)
const DEFAULT_PILOT_REPOS: PilotRepo[] = [
  { name: "anchor-example-helloworld", url: "https://github.com/coral-xyz/anchor.git", branch: "master" },
];

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const reposFile = getOptionValue(args, "--repos");
  const outputFile = getOptionValue(args, "--output") ?? "evaluation/reports/pilot-report.json";
  const workDir = getOptionValue(args, "--workdir") ?? "/tmp/hydra-pilot-repos";

  let pilotConfig: PilotConfig;

  if (reposFile) {
    const raw = await fs.readFile(path.resolve(reposFile), "utf8");
    pilotConfig = JSON.parse(raw) as PilotConfig;
  } else {
    pilotConfig = { repos: DEFAULT_PILOT_REPOS };
  }

  await fs.mkdir(workDir, { recursive: true });

  console.log(`Pilot runner: ${pilotConfig.repos.length} repo(s) to scan`);
  console.log(`Work directory: ${workDir}`);
  console.log("");

  const repoReports: RepoReport[] = [];

  for (const repo of pilotConfig.repos) {
    console.log(`[${repo.name}] Cloning/updating...`);

    let repoPath: string;
    try {
      repoPath = repo.local_path ? path.resolve(repo.local_path) : await cloneOrUpdate(repo, workDir);
    } catch (error) {
      console.log(`[${repo.name}] Clone failed: ${error instanceof Error ? error.message : "unknown"}`);
      repoReports.push({
        repo: repo.name,
        url: repo.url,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        scan_duration_ms: 0,
        error: error instanceof Error ? error.message : "clone_failed"
      });
      continue;
    }

    console.log(`[${repo.name}] Scanning...`);

    try {
      const { result, durationMs } = await scanRepo(repoPath);
      const critical = result.findings.filter((f) => f.severity === "CRITICAL").length;
      const high = result.findings.filter((f) => f.severity === "HIGH").length;
      const medium = result.findings.filter((f) => f.severity === "MEDIUM").length;
      const low = result.findings.filter((f) => f.severity === "LOW").length;

      console.log(`[${repo.name}] Done: ${result.findings.length} findings (${durationMs}ms)`);

      repoReports.push({
        repo: repo.name,
        url: repo.url,
        scan_result: result,
        findings_count: result.findings.length,
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
        scan_duration_ms: durationMs
      });
    } catch (error) {
      console.log(`[${repo.name}] Scan failed: ${error instanceof Error ? error.message : "unknown"}`);
      repoReports.push({
        repo: repo.name,
        url: repo.url,
        findings_count: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        scan_duration_ms: 0,
        error: error instanceof Error ? error.message : "scan_failed"
      });
    }
  }

  const successReports = repoReports.filter((r) => !r.error);
  const avgDuration = successReports.length > 0
    ? Math.round(successReports.reduce((sum, r) => sum + r.scan_duration_ms, 0) / successReports.length)
    : 0;

  const report: PilotReport = {
    generated_at: new Date().toISOString(),
    repos_scanned: successReports.length,
    repos_failed: repoReports.length - successReports.length,
    total_findings: repoReports.reduce((sum, r) => sum + r.findings_count, 0),
    total_critical: repoReports.reduce((sum, r) => sum + r.critical_count, 0),
    total_high: repoReports.reduce((sum, r) => sum + r.high_count, 0),
    avg_scan_duration_ms: avgDuration,
    repo_reports: repoReports.map(({ scan_result: _sr, ...rest }) => rest as RepoReport)
  };

  const outputPath = path.resolve(outputFile);
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(report, null, 2), "utf8");

  console.log("");
  console.log("=== Pilot Report ===");
  console.log(`Repos scanned: ${report.repos_scanned}/${pilotConfig.repos.length}`);
  console.log(`Total findings: ${report.total_findings} (${report.total_critical} critical, ${report.total_high} high)`);
  console.log(`Avg scan duration: ${report.avg_scan_duration_ms}ms`);
  console.log(`Report written to: ${outputPath}`);
}

main().catch((error) => {
  console.error("Pilot runner error:", error);
  process.exitCode = 1;
});
