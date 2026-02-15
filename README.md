<p align="center">
  <img src="https://img.shields.io/badge/Solana-Anchor-9945FF?style=flat-square&logo=solana&logoColor=white" alt="Solana Anchor" />
  <img src="https://img.shields.io/badge/Runtime-Bun-000000?style=flat-square&logo=bun&logoColor=white" alt="Bun" />
  <img src="https://img.shields.io/badge/Language-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript" />
  <a href="https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml"><img src="https://github.com/Pavelevich/hydra-security/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
</p>

# Hydra Security

**Multi-agent security auditing system for Solana/Anchor smart contracts.**

Hydra deploys specialized scanner agents, validates findings through an adversarial Red Team / Blue Team / Judge pipeline, and generates verified patches — all orchestrated as a concurrent agent swarm.

---

## How It Works

```
                    Target Repository
                           |
                    Threat Modeling
                           |
              +------------+------------+
              |            |            |
         Account       CPI          PDA           LLM Scanners
        Validation   Scanner      Scanner        (when API key set)
              |            |            |              |
              +------------+------------+--------------+
                           |
                    Finding Aggregation
                           |
              +------------+------------+
              |            |            |
          Red Team    Blue Team      Judge
          (attack)    (defend)     (verdict)
              |            |            |
              +------------+------------+
                           |
                    Patch Generation
                           |
                    Patch Review + Sandbox Retest
                           |
                    Final Report (Markdown / SARIF / JSON)
```

**Scanner Agents** detect domain-specific vulnerability classes in parallel:
- **Account Validation** — missing signer checks, `has_one` constraints, type confusion
- **CPI** — arbitrary cross-program invocation, signer seed bypass, reentrancy
- **PDA** — non-canonical bumps, seed collisions, attacker-controlled seeds
- **LLM-powered scanners** — same 3 domains via Claude API when `ANTHROPIC_API_KEY` is set

**Adversarial Validation** filters false positives through a 3-agent debate:
1. **Red Team** crafts exploit scenarios for each finding
2. **Blue Team** argues why the finding is a false positive
3. **Judge** renders a final verdict with confidence score

**Patch Pipeline** generates and verifies fixes:
1. Generates unified diffs for confirmed vulnerabilities
2. Applies patches with context-line verification
3. Re-runs scanners on patched code to confirm the fix

---

## Quickstart

```bash
# Install
bun install

# Run full CI (typecheck + scan + eval benchmarks)
bun run ci

# Scan a Solana project
bun run src/cli/main.ts scan /path/to/solana-project

# Scan with adversarial validation + patch generation (requires ANTHROPIC_API_KEY)
bun run src/cli/main.ts scan /path/to/project --adversarial --patch

# Diff scan (only changed files)
bun run src/cli/main.ts scan . --mode diff --base-ref origin/main --head-ref HEAD
```

---

## CLI Reference

```bash
hydra-audit scan <path>                         # Full security scan
hydra-audit scan <path> --mode diff             # Scan changed files only
hydra-audit scan <path> --adversarial --patch   # Scan + validate + patch
hydra-audit diff <path> --base-ref HEAD~3       # Diff shorthand
hydra-audit report <file> --format sarif        # Convert results to SARIF
hydra-audit config --init                       # Create .hydra.json config
hydra-audit daemon --port 8787                  # Start HTTP trigger daemon
hydra-audit github-app --port 3000              # Start GitHub App webhook server
```

---

## MCP Server (Claude Code Integration)

Hydra exposes itself as an [MCP](https://modelcontextprotocol.io) tool server, so you can invoke it from any Claude Code session.

**Setup** — add to your project's `.mcp.json` or Claude Code settings:

```json
{
  "hydra-security": {
    "command": "bun",
    "args": ["run", "/path/to/hydra-security/src/mcp/server.ts"]
  }
}
```

**Available MCP tools:**

| Tool | Description |
|------|-------------|
| `hydra_scan` | Full security scan of a target path |
| `hydra_diff_scan` | Scan only files changed between git refs |
| `hydra_report_sarif` | Convert scan results to SARIF format |
| `hydra_eval` | Run evaluation benchmarks (d1, d2, d3, d4, core, all) |
| `hydra_list_scanners` | List available scanners and their vuln classes |

---

## HTTP Daemon API

Start the daemon for CI/CD or webhook-triggered scans:

```bash
# Set auth token (recommended)
export HYDRA_DAEMON_TOKEN="your-secret-token"
export HYDRA_ALLOWED_PATHS="/home/repos,/var/projects"

bun run daemon
```

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/healthz` | GET | No | Health check |
| `/trigger` | POST | Bearer | Trigger a scan run |
| `/runs` | GET | Bearer | List all runs |
| `/runs/:id` | GET | Bearer | Get run status and results |

**Trigger a scan:**

```bash
curl -X POST http://127.0.0.1:8787/trigger \
  -H "Authorization: Bearer $HYDRA_DAEMON_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_path": "/path/to/repo", "mode": "full"}'
```

---

## GitHub Integration

Hydra runs as a GitHub App, posting inline review comments and check run results on PRs.

- **PR events** — scans changed files, posts findings as inline code annotations
- **Push events** — scans commits to the default branch, creates check runs
- **Check runs** — reports pass/fail with SARIF upload for GitHub Code Scanning

```bash
export GITHUB_APP_WEBHOOK_SECRET="your-webhook-secret"
bun run github-app
```

---

## Evaluation & Benchmarks

Hydra ships with a reproducible evaluation harness and 4 benchmark datasets:

| Dataset | Purpose | Repos |
|---------|---------|-------|
| **D1** | Seeded vulnerabilities (training set) | 1 repo, 3 vulns |
| **D2** | Seeded vulnerabilities (validation set) | 2 repos, 6 vulns |
| **D3** | Clean controls (false positive measurement) | Clean repos, 0 vulns |
| **D4** | Holdout set (generalization testing) | 2 repos, 4 vulns |

```bash
bun run eval:core     # D1 + D2 (fast, used by CI)
bun run eval:phase0   # D1 - D4 (full sweep)
bun run eval:gates    # Check V1 quality gates
```

**Current metrics (marker-based scanners):**
- D1: precision 1.000, recall 1.000
- D2: precision 1.000, recall 1.000

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANTHROPIC_API_KEY` | Enables LLM-powered scanners and adversarial pipeline | — |
| `HYDRA_DAEMON_TOKEN` | Bearer token for daemon API authentication | — (warns if unset) |
| `HYDRA_ALLOWED_PATHS` | Comma-separated allowlist for daemon scan targets | — (warns if unset) |
| `HYDRA_MAX_CONCURRENT_AGENTS` | Max scanner agents running in parallel | `3` |
| `HYDRA_AGENT_TIMEOUT_MS` | Timeout per scanner agent (ms) | `90000` |
| `HYDRA_LLM_BASE_URL` | Override Anthropic API base URL | `https://api.anthropic.com` |
| `HYDRA_LLM_MAX_RETRIES` | Max LLM API retries on transient failures | `3` |
| `HYDRA_LLM_TIMEOUT_MS` | LLM API request timeout (ms) | `120000` |

---

## Project Structure

```
src/
  agents/
    scanner/          # Vulnerability scanners (marker-based + LLM-powered)
    red-team/         # Adversarial exploit scenario generation
    blue-team/        # Defensive false-positive argumentation
    judge/            # Verdict arbitration with confidence scoring
    patch/            # Automated patch generation
    review/           # Patch review with sandbox re-validation
  orchestrator/
    run-scan.ts       # Scan orchestration (full + diff modes)
    dispatcher.ts     # Concurrent agent lifecycle management
    daemon.ts         # HTTP trigger daemon with auth
    scan-cache.ts     # Content-hash scan result caching
    threat-model-store.ts
  integrations/
    github-app.ts     # GitHub App webhook handler
    github-comments.ts # PR review comment posting
    github-checks.ts  # Check run creation + SARIF upload
  mcp/
    server.ts         # MCP tool server (stdio transport)
  llm/
    client.ts         # Anthropic API client with retry + fallback
    router.ts         # Model routing and fallback chains
    prompts.ts        # Prompt template rendering
    parser.ts         # LLM response parsing
  output/
    report.ts         # Markdown report generation
    sarif.ts          # SARIF output format
  cli/
    main.ts           # CLI entrypoint
  sandbox/            # Docker sandbox runner
evaluation/
  datasets/           # D1-D4 benchmark manifests
  scripts/            # Eval runner, prompt tuning, gate checks
  reports/            # Generated eval reports
golden_repos/         # Seeded test repositories
architecture/         # System design documents
docker/               # Hardened sandbox container
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Swarm Architecture](./architecture/swarm-architecture.md) | Multi-agent system design |
| [Solana Agents](./architecture/solana-agents.md) | Domain-specific scanner design |
| [Sandbox Security](./architecture/sandbox-security-spec.md) | Container isolation spec |
| [Implementation Plan](./plan/implementation-plan.md) | Delivery roadmap |
| [V1 Scope Lock](./plan/v1-scope-lock.md) | Scope, non-goals, done criteria |
| [Evaluation Protocol](./plan/evaluation-protocol.md) | Benchmark methodology |
| [Tech Stack](./plan/tech-stack.md) | Runtime, models, tooling decisions |

---

## Benchmark Claim Policy

No superiority claim is made without reproducible benchmark evidence. To claim "better" than any existing tool, results must pass quality gates defined in the [evaluation protocol](./plan/evaluation-protocol.md):

- Detection quality (recall + precision)
- Exploit confirmation quality
- Patch acceptance quality
- Runtime and cost profile

---

<p align="center">
  <sub>Hydra Security 2026 &mdash; Source-Available License</sub>
</p>
