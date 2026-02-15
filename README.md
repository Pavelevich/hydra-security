# Hydra Security

[![CI](https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml)

A multi-agent security auditing system with adversarial validation, specialized for Solana/Anchor smart contracts.

## Project Status: Implementation Complete (Phases 0-6)

## Quick Links

- [Architecture](./architecture/swarm-architecture.md) - Multi-agent system design
- [Solana Specialization](./architecture/solana-agents.md) - Domain-specific Solana/Anchor agents
- [Sandbox Security Spec](./architecture/sandbox-security-spec.md) - Isolation and hardening requirements
- [Implementation Plan](./plan/implementation-plan.md) - Delivery roadmap
- [V1 Scope Lock](./plan/v1-scope-lock.md) - Locked wedge, non-goals, and done criteria
- [Evaluation Protocol](./plan/evaluation-protocol.md) - Benchmark and scoring methodology
- [Tech Stack](./plan/tech-stack.md) - Runtime, models, and tooling

## Positioning

- Existing LLM-based security tools typically follow a sequential pipeline approach: threat modeling, commit scanning, sandbox validation, and patching.
- Hydra tests the hypothesis that a specialized **multi-agent swarm with adversarial validation** (Red Team vs Blue Team vs Judge) can improve detection quality in specific domains (especially Solana/Anchor), while remaining self-hostable and transparent.
- All claims are backed by reproducible benchmark evidence — no marketing without metrics.

## V1 Scope

V1 is intentionally narrow:
- Solana/Anchor-first coverage
- Three specialized scanners: Account Validation, CPI, PDA
- Adversarial validation loop: Red Team vs Blue Team vs Judge
- Patch generation and patch re-validation for confirmed findings

## Quickstart

```bash
bun install
bun run ci
bun run eval:phase0
bun run daemon
```

- `bun run ci` runs the same local validation sequence as CI: typecheck + scan + D1/D2 evaluation.
- `bun run eval:core` runs the fast benchmark set (D1+D2), used by CI.
- `bun run scan` scans the current repository and prints a markdown report.
- `bun run src/cli/main.ts scan . --mode diff` scans only files changed vs local `HEAD` diff + untracked files.
- `bun run src/cli/main.ts scan . --mode diff --base-ref origin/main --head-ref HEAD` scans only files changed between refs.
- Every scan now loads or creates a versioned threat model snapshot and includes threat-model metadata in scan output.
- Threat model cache is stored under `.hydra/threat-models/<repo-hash>/versions.json` (repo-state fingerprinted and versioned).
- `bun run eval:d1` runs the seeded D1 benchmark and writes a report to `evaluation/reports/`.
- `bun run eval:d2` runs the seeded D2 benchmark and writes a report to `evaluation/reports/`.
- `bun run eval:d3` runs clean control benchmarks (false-positive focus).
- `bun run eval:d4` runs holdout benchmarks.
- `bun run eval:phase0` runs D1-D4 sequentially (Phase 0 protocol sweep).
- `bun run eval:all` aliases `eval:phase0` (full D1-D4 sweep).
- `bun run eval:gates` checks current V1 gate status from the latest D1-D4 reports.
- `bun run daemon` starts the trigger daemon on `127.0.0.1:8787`.
- Scanner agents are now lifecycle-managed per scan (queued, running, completed/failed/timed_out) and returned in `scan` JSON output as `agent_runs`.
- Tune lifecycle limits with `HYDRA_MAX_CONCURRENT_AGENTS` and `HYDRA_AGENT_TIMEOUT_MS`.

## CLI

```bash
hydra-audit scan .                              # Full scan
hydra-audit diff . --base-ref HEAD~3            # Diff-based scan
hydra-audit report scan-result.json --format sarif --output report.sarif.json
hydra-audit config --init                       # Create .hydra.json
hydra-audit config --set min_confidence=60      # Update config
hydra-audit daemon --port 8787                  # Start HTTP daemon
hydra-audit github-app --port 3000              # Start GitHub App webhook listener
```

## Trigger API

```bash
curl -sS -X POST http://127.0.0.1:8787/trigger \
  -H 'content-type: application/json' \
  -d '{"target_path":"./golden_repos/solana_seeded_v1/repo-template-a","mode":"full","trigger":"manual"}'
```

Diff trigger example (parse git diff range):

```bash
curl -sS -X POST http://127.0.0.1:8787/trigger \
  -H 'content-type: application/json' \
  -d '{"target_path":".","mode":"diff","base_ref":"origin/main","head_ref":"HEAD","trigger":"pr-check"}'
```

```bash
curl -sS http://127.0.0.1:8787/runs
curl -sS http://127.0.0.1:8787/runs/<run_id>
```

## Sandbox Docker Setup

- Hardened sandbox container scaffolding lives in `docker/`.
- See `docker/README.md` for build/run commands and security defaults.
- Compose definition: `docker/docker-compose.yml`.

## Benchmark Claim Policy

No superiority claim is made without benchmark evidence.

To claim "better" than any existing tool, results must meet gates defined in `plan/evaluation-protocol.md`:
- Detection quality (recall/precision)
- Exploit confirmation quality
- Patch acceptance quality
- Runtime and cost profile
- Reproducible, independently reviewable methodology

---

Hydra Security 2026
