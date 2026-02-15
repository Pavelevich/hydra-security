# AgenC Security Swarm

A research and implementation project for a multi-agent security auditing system with adversarial validation and Solana/Anchor specialization.

## Project Status: Research & Design Phase

## Quick Links

- [Aardvark Analysis](./research/aardvark-analysis.md) - What is confirmed vs inferred
- [Architecture](./architecture/swarm-architecture.md) - Multi-agent system design
- [Solana Specialization](./architecture/solana-agents.md) - Domain-specific Solana/Anchor agents
- [Sandbox Security Spec](./architecture/sandbox-security-spec.md) - Isolation and hardening requirements
- [Implementation Plan](./plan/implementation-plan.md) - Delivery roadmap
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

## "Better Than Aardvark" Claim Policy

No superiority claim is made without benchmark evidence.

To claim "better," results must meet gates defined in `plan/evaluation-protocol.md`:
- Detection quality (recall/precision)
- Exploit confirmation quality
- Patch acceptance quality
- Runtime and cost profile
- Reproducible, independently reviewable methodology

---

TETSUO CORP. 2026
