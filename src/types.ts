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
  diff?: {
    base_ref?: string;
    head_ref?: string;
    changed_files: string[];
  };
}

export interface ThreatModelFingerprint {
  scan_mode: "full" | "diff";
  git_commit?: string;
  git_tree?: string;
  git_is_dirty: boolean;
  base_ref?: string;
  head_ref?: string;
  changed_files_hash: string;
}

export interface ThreatModelSummary {
  primary_language: string;
  language_breakdown: Record<string, number>;
  detected_frameworks: string[];
  assets: string[];
  trust_boundaries: string[];
  entry_points: string[];
  attack_surface: string[];
  scan_scope_files: string[];
}

export interface ThreatModelVersion {
  id: string;
  repo_id: string;
  repo_root: string;
  revision: number;
  schema_version: string;
  created_at: string;
  parent_version_id?: string;
  fingerprint_hash: string;
  fingerprint: ThreatModelFingerprint;
  summary: ThreatModelSummary;
  storage_path: string;
}

export interface ThreatModelInfo {
  version: ThreatModelVersion;
  loaded_from_cache: boolean;
}

export type AgentRunStatus = "queued" | "running" | "completed" | "failed" | "timed_out";

export interface AgentRunRecord {
  id: string;
  agent_id: string;
  status: AgentRunStatus;
  queued_at: string;
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  finding_count?: number;
  error?: string;
}

export interface ScanResult {
  target: ScanTarget;
  started_at: string;
  completed_at: string;
  threat_model?: ThreatModelInfo;
  agent_runs?: AgentRunRecord[];
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
