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
  adversarial_results?: AdversarialResult[];
}

export interface RedTeamAssessment {
  exploitable: boolean;
  exploit_code?: string;
  attack_steps: string[];
  economic_impact?: string;
  confidence: number;
  reason?: string;
  sandbox_executed: boolean;
  sandbox_exit_code?: number;
  sandbox_stdout?: string;
}

export interface BlueTeamAssessment {
  existing_mitigations: string[];
  reachable: boolean;
  reachability_reasoning: string;
  env_protections: string[];
  economically_feasible: boolean;
  overall_risk_reduction: number;
  recommendation: "confirmed" | "mitigated" | "infeasible";
}

export interface JudgeVerdict {
  verdict: "confirmed" | "likely" | "disputed" | "false_positive";
  final_severity: Severity;
  final_confidence: number;
  reasoning: string;
  evidence_summary: string;
}

export interface AdversarialResult {
  finding: Finding;
  red_team?: RedTeamAssessment;
  blue_team?: BlueTeamAssessment;
  judge?: JudgeVerdict;
}

export interface PatchProposal {
  finding_id: string;
  file: string;
  patch_diff: string;
  explanation: string;
  root_cause: string;
  test_code: string;
  breaking_changes: string[];
}

export interface ReviewIssue {
  severity: "error" | "warning" | "info";
  description: string;
}

export interface PatchReview {
  finding_id: string;
  patch_proposal: PatchProposal;
  approved: boolean;
  issues: ReviewIssue[];
  suggestions: string[];
  exploit_retest_passed?: boolean;
  regression_check_passed?: boolean;
}

export interface PatchResult {
  adversarial: AdversarialResult;
  patch?: PatchProposal;
  review?: PatchReview;
  status: "patched_and_verified" | "patched_needs_review" | "patch_rejected" | "no_patch" | "skipped";
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
