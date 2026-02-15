export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type VulnClass =
  | "missing_signer_check"
  | "missing_has_one"
  | "account_type_confusion"
  | "arbitrary_cpi"
  | "cpi_signer_seed_bypass"
  | "cpi_reentrancy"
  | "non_canonical_bump"
  | "seed_collision"
  | "attacker_controlled_seed";

export interface Finding {
  id: string;
  scanner_id: string;
  vuln_class: VulnClass;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  title: string;
  description: string;
  evidence: string;
}

export interface ScanTarget {
  root_path: string;
  mode: "full" | "diff";
}

export interface ScanResult {
  target: ScanTarget;
  started_at: string;
  completed_at: string;
  findings: Finding[];
}

export interface ExpectedFinding {
  vuln_class: VulnClass;
  severity: Severity;
  file: string;
  line: number;
  title: string;
}

export interface DatasetRepo {
  id: string;
  path: string;
  language: string;
  framework: string;
  expected_findings: ExpectedFinding[];
}

export interface DatasetManifest {
  schema_version: string;
  dataset_id: string;
  description: string;
  created_at: string;
  repos: DatasetRepo[];
}

export interface RepoScore {
  repo_id: string;
  tp: number;
  fp: number;
  fn: number;
  expected_count: number;
  predicted_count: number;
  is_clean_control: boolean;
  has_clean_fp: boolean;
  precision: number;
  recall: number;
}

export interface ScoreTotals {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  clean_repo_count: number;
  clean_repo_fp_count: number;
  clean_repo_fp_rate: number;
}

export interface SystemScore {
  system_id: string;
  repos: RepoScore[];
  totals: ScoreTotals;
}

export interface EvalReport {
  generated_at: string;
  dataset_id: string;
  systems: SystemScore[];
  notes: string[];
}
