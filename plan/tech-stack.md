# Tech Stack

## Core Runtime

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Orchestrator | **Rust** or **TypeScript (Bun)** | Performance + ecosystem. Rust for production, TS/Bun for rapid prototyping |
| Agent Communication | **JSON over stdin/stdout** | Simple, debuggable, language-agnostic |
| Task Queue | **Redis** or **In-memory** | Agent job scheduling, result collection |
| Config | **TOML** | Human-readable, widely supported |

## Detection Stack (Hybrid)

| Layer | Technology | Rationale |
|------|------------|-----------|
| Deterministic Signals | Rule/lint/static checks | Stable low-noise findings for known patterns |
| LLM Scanner Layer | Claude models | Semantic reasoning and cross-file understanding |
| Adversarial Validation | Red/Blue/Judge agents | Evidence-based exploitability filtering |
| Patch + Re-Validation | Patch + Review agents | Fix quality and regression control |

## LLM Integration

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Primary LLM | **Claude API (Anthropic)** | Best code reasoning, tool use support |
| Scanning (fast) | **Claude Haiku** | Fast + cheap for initial pass |
| Red/Blue/Judge | **Claude Opus/Sonnet** | Deep reasoning for adversarial validation |
| Patch Generation | **Claude Sonnet** | Best code generation quality/cost |
| Fallback | **GPT-4o / GPT-5** | Redundancy if Claude is down |

## Model Routing Strategy

```
Trigger → Orchestrator
    │
    ├─ Threat Model Generation → Opus (deep, runs once per repo)
    │
    ├─ Scanner Agents → Haiku (fast, parallel, many calls)
    │
    ├─ Red Team Agent → Sonnet (needs tool use + code gen)
    │
    ├─ Blue Team Agent → Sonnet (needs deep reasoning)
    │
    ├─ Judge Agent → Opus (critical decision, worth the cost)
    │
    ├─ Patch Agent → Sonnet (code generation)
    │
    └─ Review Agent → Haiku (verification is simpler than generation)
```

## Sandbox Infrastructure

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Container Runtime | **Docker** | Industry standard, easy cleanup |
| Orchestration | **Docker Compose** or **direct Docker API** | Simple, no need for K8s at this scale |
| Solana Sandbox | **solana-test-validator** in Docker | Local Solana cluster for on-chain exploits |
| Network | **--network=none** | Complete isolation |
| Cleanup | **Ephemeral containers** | Destroy after each validation |
| Time Limit | **60s per exploit attempt** | Prevent infinite loops |

Security controls (required):
- Non-root runtime
- Read-only root filesystem
- Capability drop + seccomp/AppArmor policy
- Strict CPU/memory/pids/time limits
- Artifact sanitization and immutable audit logs

Reference: `architecture/sandbox-security-spec.md`

## Git Integration

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Git Operations | **libgit2** (Rust) or **simple-git** (JS) | Parse commits, diffs, blame |
| GitHub API | **Octokit** or **gh CLI** | PR creation, comments, checks |
| Webhook Server | **Express/Hono** (TS) or **Axum** (Rust) | Receive GitHub webhooks |
| Auth | **GitHub App** | Per-repo installation, fine-grained permissions |

## Storage

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Threat Models | **JSON files in repo** (.hydra-security/) | Versioned with code |
| Scan Results | **SQLite** | Simple, portable, no external deps |
| Agent Logs | **File-based** (structured JSON) | Debug + audit trail |
| Cache | **Redis** or **File-based** | Threat model cache, scan result cache |

## Output Formats

| Format | Purpose |
|--------|---------|
| **SARIF** | GitHub Security tab integration |
| **Markdown** | Human-readable reports |
| **JSON** | Machine-readable findings |
| **GitHub PR** | Patches with inline annotations |
| **Slack webhook** | Real-time notifications |

## Development Tools

| Tool | Purpose |
|------|---------|
| **Bun** | TypeScript runtime + package manager |
| **Cargo** | Rust build system |
| **Docker** | Sandbox containers |
| **GitHub Actions** | CI/CD for the tool itself |
| **Anchor CLI** | Solana program testing |
| **solana-test-validator** | Local Solana cluster |

## Cost Estimation (Per Full Repo Scan)

Assuming a medium-sized repo (~50k lines).
This is a planning estimate; production numbers must come from measured telemetry.

| Agent | Model | Calls | Tokens/Call | Cost/Call | Total |
|-------|-------|-------|-------------|-----------|-------|
| Threat Model | Opus | 1 | ~50k | ~$0.75 | $0.75 |
| Scanners (8x) | Haiku | 8 | ~20k | ~$0.01 | $0.08 |
| Red Team | Sonnet | ~5 | ~30k | ~$0.15 | $0.75 |
| Blue Team | Sonnet | ~5 | ~30k | ~$0.15 | $0.75 |
| Judge | Opus | ~5 | ~10k | ~$0.15 | $0.75 |
| Patch | Sonnet | ~3 | ~20k | ~$0.10 | $0.30 |
| Review | Haiku | ~3 | ~15k | ~$0.01 | $0.03 |
| **TOTAL** | | | | | **~$3.41** |

Use `plan/evaluation-protocol.md` to track real cost/quality tradeoffs.

## Directory Structure

```
hydra-security/
├── Cargo.toml              # Rust workspace (if Rust)
├── package.json            # Node/Bun workspace (if TS)
├── docker/
│   ├── sandbox/
│   │   ├── Dockerfile.generic    # Generic exploit sandbox
│   │   └── Dockerfile.solana     # Solana test validator sandbox
│   └── docker-compose.yml
├── src/
│   ├── orchestrator/
│   │   ├── mod.rs
│   │   ├── trigger.rs        # Git webhook / CLI handler
│   │   ├── threat_model.rs   # Threat model generation + cache
│   │   ├── dispatcher.rs     # Agent spawning + scheduling
│   │   └── aggregator.rs     # Result collection + dedup
│   ├── agents/
│   │   ├── scanner/
│   │   │   ├── injection.rs
│   │   │   ├── auth.rs
│   │   │   ├── logic.rs
│   │   │   ├── solana_accounts.rs
│   │   │   ├── solana_cpi.rs
│   │   │   ├── solana_pda.rs
│   │   │   ├── solana_economic.rs
│   │   │   ├── solana_state.rs
│   │   │   └── solana_math.rs
│   │   ├── red_team.rs
│   │   ├── blue_team.rs
│   │   ├── judge.rs
│   │   ├── patch.rs
│   │   └── review.rs
│   ├── sandbox/
│   │   ├── docker.rs         # Container management
│   │   ├── solana.rs         # Solana test validator management
│   │   └── executor.rs       # Run exploit in sandbox
│   ├── llm/
│   │   ├── client.rs         # Claude/OpenAI API client
│   │   ├── prompts/          # Prompt templates per agent
│   │   ├── router.rs         # Model selection per task
│   │   └── parser.rs         # Response parsing
│   ├── output/
│   │   ├── sarif.rs          # SARIF format
│   │   ├── report.rs         # Markdown report
│   │   ├── github_pr.rs      # PR creation
│   │   └── slack.rs          # Notifications
│   └── cli/
│       └── main.rs           # CLI interface
├── prompts/
│   ├── threat_model.md
│   ├── scanner_injection.md
│   ├── scanner_auth.md
│   ├── scanner_solana_accounts.md
│   ├── red_team.md
│   ├── blue_team.md
│   ├── judge.md
│   ├── patch.md
│   └── review.md
├── golden_repos/             # Test repos with known vulns
│   ├── web_app_vulns/
│   └── solana_program_vulns/
└── tests/
    ├── integration/
    └── benchmarks/
```
