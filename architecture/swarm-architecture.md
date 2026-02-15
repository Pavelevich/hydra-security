# Swarm Architecture - Multi-Agent Security System

## Design Philosophy

Use a **swarm of specialized agents** that operate in parallel, cross-validate findings, and use adversarial dynamics to reduce false positives in a transparent way.

Note: This is a proposed architecture. Performance/superiority claims are hypotheses until validated by `plan/evaluation-protocol.md`.

## High-Level Architecture

```
GitHub Webhook / Git Hook / CLI Trigger
    |
    v
┌──────────────────────────────────────────────────────┐
│                   ORCHESTRATOR                        │
│                                                      │
│  - Receives trigger (commit, PR, manual scan)        │
│  - Loads/updates threat model                        │
│  - Determines scan scope (diff vs full repo)         │
│  - Spawns scanner agents in parallel                 │
│  - Collects candidate vulnerabilities                │
│  - Spawns adversarial validation pairs               │
│  - Aggregates final results                          │
│  - Generates report / creates PR                     │
└──────────────────┬───────────────────────────────────┘
                   │
    ┌──────────────┼──────────────────────┐
    │              │                      │
    v              v                      v
┌─────────┐  ┌─────────┐           ┌─────────┐
│SCANNER 1│  │SCANNER 2│    ...    │SCANNER N│
│Injection│  │Auth/Authz│          │Logic    │
└────┬────┘  └────┬────┘           └────┬────┘
     │            │                     │
     v            v                     v
┌──────────────────────────────────────────────────────┐
│              CANDIDATE POOL                           │
│  Deduplicated, normalized vulnerability candidates    │
└──────────────────────┬───────────────────────────────┘
                       │
            ┌──────────┼──────────┐
            v                     v
    ┌──────────────┐     ┌──────────────┐
    │  RED TEAM    │     │  BLUE TEAM   │
    │  AGENT       │     │  AGENT       │
    │              │     │              │
    │  - Writes    │     │  - Argues    │
    │    exploit   │     │    false     │
    │  - Runs in   │     │    positive  │
    │    sandbox   │     │  - Finds     │
    │  - Documents │     │    existing  │
    │    attack    │     │    mitigations│
    │    chain     │     │              │
    └──────┬───────┘     └──────┬───────┘
           │                    │
           v                    v
    ┌──────────────────────────────────────┐
    │           JUDGE AGENT                 │
    │                                      │
    │  - Weighs red vs blue evidence       │
    │  - Assigns severity (CVSS-like)      │
    │  - Assigns confidence score 0-100    │
    │  - Filters: only HIGH confidence     │
    │    findings proceed                  │
    └──────────────┬───────────────────────┘
                   │
                   v
    ┌──────────────────────────────────────┐
    │          PATCH AGENT                  │
    │                                      │
    │  - Generates minimal fix             │
    │  - Ensures fix doesn't break tests   │
    │  - Follows project code style        │
    └──────────────┬───────────────────────┘
                   │
                   v
    ┌──────────────────────────────────────┐
    │         REVIEW AGENT                  │
    │                                      │
    │  - Re-scans the patch for new vulns  │
    │  - Verifies the original vuln is     │
    │    actually fixed                    │
    │  - Checks for regression             │
    └──────────────┬───────────────────────┘
                   │
                   v
    ┌──────────────────────────────────────┐
    │          OUTPUT                       │
    │                                      │
    │  - GitHub PR with findings + patches │
    │  - Security report (severity ranked) │
    │  - Exploit PoCs for each finding     │
    │  - Red vs Blue reasoning trace       │
    └──────────────────────────────────────┘
```

## Agent Definitions

### 1. Orchestrator Agent
**Role**: Central coordinator
**Responsibilities**:
- Parse trigger event (commit SHA, PR number, or full-scan request)
- Load or generate threat model for the repo
- Determine which files changed and which scanners are relevant
- Spawn scanner agents in parallel
- Collect and deduplicate candidate vulnerabilities
- Spawn Red/Blue pairs for each candidate
- Aggregate judge decisions
- Trigger patch generation for confirmed vulns
- Format final output

**Context**: Has access to threat model, repo metadata, git history

### 2. Scanner Agents (Parallel, Specialized)
**Role**: Domain-specific vulnerability detection
**Instances**: One per vulnerability class (see below)
**Input**: Threat model + relevant code files + git diff
**Output**: List of candidate vulnerabilities with:
  - File path + line numbers
  - Vulnerability class
  - Description of the issue
  - Potential impact
  - Initial confidence score

**Scanner Types**:

| Scanner | Focus Area |
|---------|-----------|
| Injection Scanner | SQLi, XSS, Command Injection, SSTI, Path Traversal, LDAP Injection |
| Auth Scanner | Broken authentication, session management, privilege escalation, IDOR |
| Crypto Scanner | Weak algorithms, key management, RNG issues, timing attacks |
| Logic Scanner | Race conditions, TOCTOU, business logic flaws, state machine errors |
| Data Scanner | Information disclosure, PII leaks, sensitive data in logs, hardcoded secrets |
| Config Scanner | Misconfigurations, default credentials, overly permissive settings |
| Dependency Scanner | Known CVEs in dependencies, outdated packages, supply chain risks |
| API Scanner | Broken object-level auth, mass assignment, rate limiting, SSRF |

### 3. Red Team Agent
**Role**: Attacker -- prove the vulnerability is real
**Input**: Candidate vulnerability + full repo context
**Process**:
1. Analyze the vulnerable code path
2. Craft an exploit payload
3. Write a PoC script
4. Execute in sandbox environment
5. Document the complete attack chain
6. Assess real-world exploitability

**Output**: Exploit PoC + execution result + attack chain documentation

### 4. Blue Team Agent
**Role**: Defender -- argue it's a false positive
**Input**: Same candidate vulnerability + full repo context
**Process**:
1. Look for existing mitigations (WAF, input validation, etc.)
2. Check if the vulnerable path is actually reachable
3. Verify if runtime protections prevent exploitation
4. Assess if the environment configuration blocks the attack
5. Look for compensating controls
6. Argue why this is NOT exploitable

**Output**: Defense analysis + evidence for/against false positive

### 5. Judge Agent
**Role**: Impartial evaluator
**Input**: Red Team evidence + Blue Team evidence
**Process**:
1. Weigh the exploit PoC (did it actually work in sandbox?)
2. Weigh the defensive arguments
3. Consider the threat model context
4. Assign CVSS-like severity score
5. Assign confidence score (0-100)
6. Make GO/NO-GO decision (threshold: 70+ confidence)

**Output**: Verdict + severity + confidence + reasoning

### 6. Patch Agent
**Role**: Fix generator
**Input**: Confirmed vulnerability + exploit PoC + repo context
**Process**:
1. Understand the root cause from red team's analysis
2. Generate minimal, targeted fix
3. Follow project's existing code style/patterns
4. Ensure fix addresses root cause, not just symptom
5. Run existing test suite to check for regression

**Output**: Git patch + explanation of changes

### 7. Review Agent
**Role**: Patch validator
**Input**: Original vulnerability + generated patch
**Process**:
1. Apply patch to codebase
2. Re-run the Red Team's exploit PoC (should fail now)
3. Scan patch itself for new vulnerabilities
4. Check for unintended side effects
5. Verify code style compliance

**Output**: APPROVE / REJECT + reasoning

## Expected Advantages Over Sequential Pipelines (Hypothesis)

| Dimension | Sequential LLM Pipeline | Our Swarm |
|-----------|------------------------|-----------|
| Speed | Sequential scan | Parallel scanners (Nx faster) |
| Depth | One context for everything | Dedicated context per agent |
| False Positives | Self-validates (bias risk) | Adversarial Red vs Blue |
| Specialization | Generic | Domain-specific scanners |
| Transparency | Black box | Full reasoning traces |
| Customization | SaaS product model | Fully configurable pipeline |
| Large Repos | Context window limited | Distributed across agents |
| Patch Quality | Single attempt | Generate + adversarial review |

## Communication Protocol

Agents communicate via structured JSON messages:

```json
{
  "agent_id": "scanner-injection-001",
  "type": "candidate_vulnerability",
  "timestamp": "2026-02-15T12:00:00Z",
  "payload": {
    "file": "src/api/handlers/user.rs",
    "lines": [142, 158],
    "vuln_class": "sql_injection",
    "description": "User input from query param 'search' passed directly to SQL query without parameterization",
    "severity_estimate": "HIGH",
    "confidence": 85,
    "context": {
      "function": "handle_search",
      "input_source": "HTTP query parameter",
      "sink": "sqlx::query! macro with format string"
    }
  }
}
```

## Failure Modes & Mitigations

| Failure | Mitigation |
|---------|-----------|
| Scanner misses a vuln class | Overlap between scanners; Logic Scanner catches what others miss |
| Red Team can't write working exploit | Lower confidence score; still report as "unconfirmed potential" |
| Blue Team always wins (too defensive) | Judge weights sandbox execution results highest |
| Patch introduces new vuln | Review Agent catches it; cycle back to Red Team |
| Orchestrator overwhelmed | Rate limiting; priority queue by severity estimate |
| Sandbox escape | Containerized with no network; ephemeral; destroyed after each run |
