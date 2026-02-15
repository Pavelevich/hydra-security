# V1 Scope Lock

## Objective

Define the strict delivery boundary for Hydra V1 so execution stays narrow, benchmarkable, and defensible.

## Locked Wedge

- Domain: **Solana/Anchor repositories only**
- Detection classes (V1): **Account Validation, CPI Security, PDA Security**
- Execution mode: repository-level full scan and dataset-driven evaluation

## In-Scope Components

- Three V1 scanners:
  - `scanner.solana.account-validation`
  - `scanner.solana.cpi`
  - `scanner.solana.pda`
- Evaluation datasets: D1, D2, D3, D4
- Baselines:
  - `baseline-single-agent`
  - `baseline-deterministic`
- Reporting:
  - JSON evaluation reports
  - gate check output (`bun run eval:gates`)

## Explicit Non-Goals for V1

- Broad multi-language support outside Solana/Anchor
- Full exploit sandbox loop (Red/Blue/Judge execution evidence)
- Automated patch generation + patch re-validation
- Production GitHub App / PR bot integration
- Cost telemetry and median scan time SLA enforcement
- Public “better than Aardvark overall” claims

## V1 Done Criteria (Pilot Entry)

1. **Evaluation Harness**
   - D1-D4 manifests available and versioned
   - Baseline comparisons run successfully on all datasets
   - Gate script available and reproducible

2. **Detection Quality**
   - Recall gate passes on D1+D2
   - Precision gate passes on D1+D2+D3
   - D4 holdout results produced for each release candidate

3. **Operational Readiness**
   - Local CI command (`bun run ci`) passes
   - GitHub Actions CI passes on `main`
   - Report schema and finding schema remain stable

## Claim Guardrail

Allowed statement pattern:
- “Hydra outperforms baseline X on dataset Y for metric Z under this protocol.”

Disallowed statement pattern:
- “Hydra is better than Aardvark overall.”
