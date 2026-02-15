import path from "node:path";
import { promises as fs } from "node:fs";
import { dispatchScanners } from "./dispatcher";
import { aggregateFindings } from "./aggregator";
import type { ScanResult, ScanTarget } from "../types";
import { resolveDiffSelection } from "./git-diff";
import { loadOrCreateThreatModel } from "./threat-model-store";

export interface DiffScanOptions {
  baseRef?: string;
  headRef?: string;
  changedFiles?: string[];
}

async function normalizeChangedFiles(rootPath: string, changedFiles: string[]): Promise<string[]> {
  const normalized = new Set<string>();
  for (const filePath of changedFiles) {
    const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(rootPath, filePath);
    try {
      const stat = await fs.stat(absolutePath);
      if (stat.isFile()) {
        normalized.add(absolutePath);
      }
    } catch {
      // Ignore deleted/unreachable paths.
    }
  }
  return [...normalized];
}

export async function runFullScan(rootPath: string): Promise<ScanResult> {
  const target: ScanTarget = {
    root_path: path.resolve(rootPath),
    mode: "full"
  };

  const threatModel = await loadOrCreateThreatModel(target);
  const started = new Date().toISOString();
  const dispatched = await dispatchScanners(target);
  const findings = aggregateFindings(dispatched.findings);
  const completed = new Date().toISOString();

  return {
    target,
    started_at: started,
    completed_at: completed,
    threat_model: threatModel,
    agent_runs: dispatched.agent_runs,
    findings
  };
}

export async function runDiffScan(
  rootPath: string,
  options: DiffScanOptions = {}
): Promise<ScanResult> {
  const resolvedRoot = path.resolve(rootPath);
  const resolvedDiff = options.changedFiles
    ? {
        baseRef: options.baseRef,
        headRef: options.headRef,
        changedFiles: await normalizeChangedFiles(resolvedRoot, options.changedFiles)
      }
    : await resolveDiffSelection(resolvedRoot, {
        baseRef: options.baseRef,
        headRef: options.headRef,
        includeUntracked: true
      });

  const target: ScanTarget = {
    root_path: resolvedRoot,
    mode: "diff",
    diff: {
      base_ref: resolvedDiff.baseRef,
      head_ref: resolvedDiff.headRef,
      changed_files: resolvedDiff.changedFiles
    }
  };

  const threatModel = await loadOrCreateThreatModel(target);
  const started = new Date().toISOString();
  if (resolvedDiff.changedFiles.length === 0) {
    const completed = new Date().toISOString();
    return {
      target,
      started_at: started,
      completed_at: completed,
      threat_model: threatModel,
      agent_runs: [],
      findings: []
    };
  }

  const dispatched = await dispatchScanners(target);
  const changedSet = new Set(resolvedDiff.changedFiles.map((filePath) => path.resolve(filePath)));
  const findings = aggregateFindings(dispatched.findings).filter((finding) =>
    changedSet.has(path.resolve(finding.file))
  );
  const completed = new Date().toISOString();

  return {
    target,
    started_at: started,
    completed_at: completed,
    threat_model: threatModel,
    agent_runs: dispatched.agent_runs,
    findings
  };
}
