# Prior Art - LLM-Based Security Pipeline Analysis

## Evidence Levels

This document separates:
- **Confirmed**: Publicly documented patterns in LLM-based security tooling.
- **Inferred**: Reasonable interpretation from public descriptions.
- **Hypothesis**: Competitive assumptions to test, not facts.

## Overview

- **What**: LLM-based agentic security researchers represent a new class of vulnerability detection tools
- **Trend**: Multiple vendors announced LLM-powered security agents in 2025
- **Status**: Various stages from private beta to production
- **Purpose**: Autonomously detect, validate, and fix code vulnerabilities

## Common Pipeline Pattern

Most LLM-based security tools follow a similar 4-stage flow:

### Stage 1: Repository Analysis (Threat Modeling)
- Analyzes the entire repository
- Produces a threat model reflecting security objectives and design
- Maps dependencies, architectural patterns, potential weak points
- This threat model becomes context for all subsequent scanning

### Stage 2: Commit-Level Scanning
- Monitors every new commit against the full repo + threat model
- Also scans historical commit history for latent issues
- Detects: security vulnerabilities, logic errors, incomplete fixes, privacy issues
- Embeds directly into CI/CD pipeline (GitHub integration)

### Stage 3: Sandbox Validation (Exploit Confirmation)
- When a potential vulnerability is found, attempts to exploit it
- Uses isolated, sandboxed environment
- Confirms the vulnerability is exploitable in practice, not just theory
- Only confirmed threats are reported (reduces false positives)
- Provides step-by-step explanations with annotated code snippets

### Stage 4: Automated Patching
- Integrates with coding agents
- Generates precise patch for each confirmed vulnerability
- Patch is also scanned before being proposed
- Human review workflow

## Likely Design Characteristics (Inferred)

### LLM-Centered Reasoning
- Does NOT use fuzzing
- Does NOT use software composition analysis (SCA)
- Does NOT use pattern matching / signature-based detection
- Instead: "reads code like a human security researcher"
- Uses LLM reasoning + tool-use to understand code behavior

### Performance
- Industry benchmarks claim ~92% detection rate on known + synthetically-injected vulnerabilities
- Outperforms traditional scanning tools in both recall and precision
- CVEs discovered and responsibly disclosed in open-source projects

## Comparison: LLM Pipelines vs Traditional Tools

| Aspect               | Traditional (SAST/DAST) | LLM Pipeline           |
|----------------------|------------------------|------------------------|
| Method               | Pattern matching        | LLM reasoning          |
| Approach             | Rule-based signatures   | Human-like code reading|
| Validation           | Flags patterns          | Exploits in sandbox    |
| False positives      | High                   | Low (confirmed only)   |
| Patching             | None                   | Auto-generate + scan   |
| Context understanding| Minimal                | Full repo threat model |

## Strengths of Pipeline Approach
1. End-to-end pipeline (detect + validate + patch)
2. Sandbox confirmation eliminates false positives
3. GitHub-native integration
4. Generated patches are re-scanned

## Hydra's Competitive Design Hypotheses

These are design hypotheses for Hydra, not proven weaknesses of existing tools:
1. **Adversarial validation may lower false positives further** than single-loop validation.
2. **Domain-specialized Solana/Anchor agents may outperform generic scanners** on Solana-specific bug classes.
3. **Parallel specialist scanners may improve wall-clock latency** on larger repositories.
4. **Self-hosted transparency and customization** can be a differentiator for teams with strict control requirements.
5. **Multi-model routing may optimize cost-quality tradeoffs** versus fixed-model pipelines.

## What We Should Not Claim Without Evidence

- "Hydra is better than any specific tool overall."
- "Hydra has lower false positive rate than existing tools."

These statements require direct benchmark evidence under a defined protocol.
