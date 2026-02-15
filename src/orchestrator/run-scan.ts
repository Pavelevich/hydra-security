import path from "node:path";
import { dispatchScanners } from "./dispatcher";
import { aggregateFindings } from "./aggregator";
import type { ScanResult, ScanTarget } from "../types";

export async function runFullScan(rootPath: string): Promise<ScanResult> {
  const target: ScanTarget = {
    root_path: path.resolve(rootPath),
    mode: "full"
  };

  const started = new Date().toISOString();
  const rawFindings = await dispatchScanners(target);
  const findings = aggregateFindings(rawFindings);
  const completed = new Date().toISOString();

  return {
    target,
    started_at: started,
    completed_at: completed,
    findings
  };
}
