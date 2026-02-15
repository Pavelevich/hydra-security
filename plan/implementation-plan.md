# Implementation Plan

## Guiding Principles

- Scope narrow before scaling breadth.
- Benchmark before marketing claims.
- Hybrid detection over LLM-only detection.
- Security hardening is a blocker, not an optional task.

## Phase 0: Scope Lock + Evaluation Harness (Week 1)

### 0.1 V1 Scope Lock
- [x] Lock V1 wedge to Solana/Anchor
- [x] Lock V1 scanners to: Account Validation, CPI, PDA
- [x] Define non-goals for V1 (defer broad generic scanner set)
- [x] Define "done" criteria for pilot

### 0.2 Evaluation Protocol
- [x] Finalize `plan/evaluation-protocol.md`
- [x] Build dataset manifests (D1-D4)
- [x] Implement common finding schema
- [x] Implement baseline runner (deterministic + single-agent)
- [x] Implement metric computation script

## Phase 1: Foundation (Week 1-2)

### 1.1 Project Setup
- [x] Initialize repo (Rust + TypeScript monorepo)
- [x] Define agent communication protocol (JSON schema)
- [x] Set up CI/CD (GitHub Actions)
- [x] Docker setup for sandbox environments

### 1.2 Core Orchestrator
- [x] Build orchestrator daemon (receives triggers, spawns agents)
- [ ] Git integration (parse commits, diffs, PR events)
- [ ] Threat model storage and versioning
- [ ] Agent lifecycle management (spawn, monitor, collect results)
- [x] Result aggregation and deduplication

### 1.3 Hybrid Detection Layer
- [x] Add deterministic signal adapters (rules/lints/static checks)
- [x] Define merge strategy for deterministic + LLM findings
- [x] Add normalization layer into candidate pool

### 1.4 LLM Integration Layer
- [ ] Claude API client with retry/fallback
- [ ] Prompt template system (per agent type)
- [ ] Token budget management (allocate context per agent)
- [ ] Response parsing and validation
- [ ] Streaming support for long-running analysis

## Phase 2: Scanner Agents (Week 2-4)

### 2.1 Solana V1 Scanners
- [x] Account Validation Agent
- [x] CPI Security Agent
- [x] PDA Security Agent

### 2.2 Scanner Testing
- [x] Create "golden" repos with known vulnerabilities
- [x] Benchmark each scanner independently
- [x] Measure recall and precision per vulnerability class
- [ ] Tune prompts based on results

## Phase 3: Adversarial Validation (Week 4-6)

### 3.1 Sandbox Infrastructure
- [ ] Docker-based sandbox environment
- [ ] Solana test validator sandbox (for on-chain exploits)
- [ ] Network isolation (no outbound connections)
- [ ] Ephemeral containers (destroy after each validation)
- [ ] Resource limits (CPU, memory, time)
- [ ] Implement all hardening controls in `architecture/sandbox-security-spec.md`

### 3.2 Red Team Agent
- [ ] Exploit generation from vulnerability description
- [ ] PoC script writing (Python, Rust, JS depending on target)
- [ ] Sandbox execution and result capture
- [ ] Attack chain documentation
- [ ] Solana-specific: transaction construction + local validator execution

### 3.3 Blue Team Agent
- [ ] Mitigation discovery (find existing defenses in codebase)
- [ ] Reachability analysis (is the vulnerable path actually reachable?)
- [ ] Environment check (do runtime protections block the attack?)
- [ ] Economic feasibility analysis (is it profitable to exploit?)
- [ ] Argument construction with evidence

### 3.4 Judge Agent
- [ ] Evidence weighing system (sandbox result > theoretical analysis)
- [ ] CVSS-like severity scoring
- [ ] Confidence scoring (0-100)
- [ ] Threshold-based filtering (configurable)
- [ ] Reasoning trace output

## Phase 4: Patching & Review (Week 6-8)

### 4.1 Patch Agent
- [ ] Root cause analysis from Red Team findings
- [ ] Minimal fix generation (don't over-engineer)
- [ ] Code style matching (follow project conventions)
- [ ] Test generation for the fix

### 4.2 Review Agent
- [ ] Re-run Red Team exploit against patched code
- [ ] Scan patch for introduced vulnerabilities
- [ ] Regression check (run existing tests)
- [ ] Side effect analysis

### 4.3 Output Generation
- [ ] GitHub PR creation with findings + patches
- [ ] Security report (Markdown + JSON)
- [ ] SARIF format output (for GitHub Security tab integration)
- [ ] Slack/Discord notification integration

## Phase 5: Integration & Pilot (Week 8-12)

### 5.1 GitHub Integration
- [ ] GitHub App for webhook reception
- [ ] PR comment bot (inline vulnerability annotations)
- [ ] GitHub Check integration (pass/fail on security)
- [ ] SARIF upload to GitHub Security tab

### 5.2 CLI Tool
- [ ] `hydra-audit scan <repo>` - Full scan
- [ ] `hydra-audit diff <commit>` - Diff-based scan
- [ ] `hydra-audit report` - Generate report
- [ ] `hydra-audit config` - Configure scanners/thresholds

### 5.3 Pilot
- [ ] Pilot on 5-10 real Solana/Anchor repos
- [ ] Run full evaluation protocol weekly
- [ ] Publish benchmark report with raw evidence
- [ ] Decide go/no-go for expanding scanner coverage

### 5.4 Dashboard (Optional)
- [ ] Web UI showing scan history
- [ ] Vulnerability trends over time
- [ ] Agent performance metrics
- [ ] False positive tracking

## Phase 6: Optimization (Ongoing)

### 6.1 Prompt Engineering
- [ ] A/B test different prompts per scanner
- [ ] Build prompt evaluation dataset
- [ ] Track recall/precision over time
- [ ] Domain-specific prompt tuning

### 6.2 Performance
- [ ] Cache threat models (only rebuild on major changes)
- [ ] Incremental scanning (only scan changed files + dependencies)
- [ ] Agent result caching (don't re-scan unchanged code)
- [ ] Parallel execution tuning (optimal number of concurrent agents)

### 6.3 Model Selection
- [ ] Use fast model (Haiku) for initial scanning
- [ ] Use deep model (Opus/Sonnet) for Red/Blue/Judge
- [ ] Evaluate cost vs quality tradeoffs
- [ ] Implement model routing based on task complexity

## Milestones

| Milestone | Target | Deliverable |
|-----------|--------|-------------|
| M0 | Week 1 | Scope lock + evaluation harness scaffold |
| M1 | Week 2 | Orchestrator + hybrid candidate pool working |
| M2 | Week 4 | 3 Solana scanners working end-to-end |
| M3 | Week 6 | Red/Blue/Judge adversarial loop working |
| M4 | Week 8 | Patch generation + review loop |
| M5 | Week 10 | GitHub integration + CLI tool |
| M6 | Week 12 | Pilot benchmark report with reproducible metrics |

## Success Metrics

Use metrics and formulas defined in `plan/evaluation-protocol.md`.

V1 gates:
- **Recall**: >= 0.85 on D1+D2
- **Precision**: >= 0.80 on D1+D2+D3
- **Exploit Confirmation Precision**: >= 0.90
- **Patch Acceptance Rate**: >= 0.70
- **Median Full Scan Time**: <= 10 minutes on reference repo size
