# Evaluation Protocol

## Objective

Define a reproducible way to measure whether Hydra is actually better on its target domain.

Primary question:
- Does Hydra improve vulnerability detection quality and patch reliability for Solana/Anchor repositories while maintaining acceptable runtime and cost?

## Claim Policy

Allowed claims:
- "Better than baseline X on dataset Y with metric Z."

Disallowed claims:
- "Better than Aardvark overall" without head-to-head comparable evidence.

## Scope

V1 evaluation scope:
- Solana/Anchor repositories
- Vulnerability classes: account validation, CPI security, PDA security
- Full flow: detection -> adversarial validation -> patch -> patch re-validation

## Baselines

Evaluate against at least these baselines:
1. Deterministic static analysis baseline (rules/lints)
2. Single-agent LLM baseline (no Red/Blue/Judge loop)
3. Human adjudication ground truth (for disputed cases)

Reference-only benchmark:
- Publicly reported Aardvark metrics may be used for context, not as direct head-to-head proof.

## Dataset Design

### D1 - Seeded Solana Corpus
- 20-40 Solana/Anchor repos with injected known vulnerabilities.
- Each injection tagged by class and exact location.

### D2 - Historical Real Issues
- Repositories with publicly documented security fixes.
- Ground truth derived from patch diffs and issue history.

### D3 - Clean Control Set
- Repositories reviewed as "no known security issue" in target classes.
- Used to estimate false positive behavior.

### D4 - Holdout Set
- Never used for prompt tuning.
- Used only for final reported metrics.

## Data Hygiene Rules

- Freeze datasets per evaluation run.
- Version dataset manifests in git.
- Keep prompt tuning and final scoring on separate splits.
- Record commit SHAs for every scanned repository.

## Metrics

Core metrics:
1. **Recall** = TP / (TP + FN)
2. **Precision** = TP / (TP + FP)
3. **False Positive Rate** = FP / (FP + TN)
4. **Exploit Confirmation Precision** = confirmed_exploits / exploit_attempts
5. **Patch Acceptance Rate** = accepted_patches / proposed_patches
6. **Patch Non-Regression Rate** = patches_with_no_regression / accepted_patches
7. **Median Time to First High-Confidence Finding**
8. **Median End-to-End Scan Time**
9. **Cost per Repository Scan**

Calibration metrics:
1. Confidence bucket accuracy (0-20, 21-40, ..., 81-100)
2. Brier score (optional in V1)

## Scoring Workflow

1. Run all systems on the same frozen dataset snapshot.
2. Normalize output to a common finding schema.
3. Match findings to ground truth using file, line, class, and semantic equivalence.
4. Send disputed matches to human adjudication.
5. Compute metrics and confidence intervals.
6. Publish raw outputs and summary report.

## Human Adjudication

- Use two reviewers for disputed cases.
- If disagreement persists, use a third reviewer.
- Log adjudication rationale for auditability.

## Release Gates

### V1 Internal Gate
- Recall >= 0.85 on D1+D2
- Precision >= 0.80 on D1+D2+D3
- Exploit Confirmation Precision >= 0.90
- Patch Acceptance Rate >= 0.70
- Median full scan <= 10 minutes (reference repo size: ~50k LOC)

### "Stronger Than Baseline" Gate
- Recall and precision must both exceed single-agent baseline by >= 10% relative.
- No regression in patch non-regression rate.

## Report Template

Each evaluation report must include:
- Dataset snapshot ID
- Baseline versions and configurations
- Hydra version and prompt set version
- Metric table with confidence intervals
- Error analysis (top false positives and false negatives)
- Cost and runtime summary

## Cadence

- Quick eval: every major merge to `main` (D1 subset)
- Full eval: weekly (D1-D4)
- Public claim eval: on tagged releases only
