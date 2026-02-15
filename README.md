# Hydra Security

[![CI](https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml)

A research and implementation project for a multi-agent security auditing system with adversarial validation and Solana/Anchor specialization.

## Project Status: Research & Design Phase

## Quick Links

- [Aardvark Analysis](./research/aardvark-analysis.md) - What is confirmed vs inferred
- [Architecture](./architecture/swarm-architecture.md) - Multi-agent system design
- [Solana Specialization](./architecture/solana-agents.md) - Domain-specific Solana/Anchor agents
- [Sandbox Security Spec](./architecture/sandbox-security-spec.md) - Isolation and hardening requirements
- [Implementation Plan](./plan/implementation-plan.md) - Delivery roadmap
- [V1 Scope Lock](./plan/v1-scope-lock.md) - Locked wedge, non-goals, and done criteria
- [Evaluation Protocol](./plan/evaluation-protocol.md) - Benchmark and scoring methodology
- [Tech Stack](./plan/tech-stack.md) - Runtime, models, and tooling

## Positioning

- OpenAI publicly documents Aardvark as a 4-stage pipeline: threat modeling, commit scanning, sandbox validation, and patching.
- OpenAI does not publicly disclose every internal architectural detail.
- This project tests the hypothesis that a specialized multi-agent swarm can improve outcomes in specific domains (especially Solana/Anchor), while remaining self-hostable and transparent.

## V1 Scope

V1 is intentionally narrow:
- Solana/Anchor-first coverage
- Three specialized scanners: Account Validation, CPI, PDA
- Adversarial validation loop: Red Team vs Blue Team vs Judge
- Patch generation and patch re-validation for confirmed findings

## Scaffold Quickstart

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

Trigger API:

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

## "Better Than Aardvark" Claim Policy

No superiority claim is made without benchmark evidence.

To claim "better," results must meet gates defined in `plan/evaluation-protocol.md`:
- Detection quality (recall/precision)
- Exploit confirmation quality
- Patch acceptance quality
- Runtime and cost profile
- Reproducible, independently reviewable methodology

---

Hydra Security 2026
