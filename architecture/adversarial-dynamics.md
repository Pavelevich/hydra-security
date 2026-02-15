# Adversarial Dynamics: Red Team vs Blue Team

## The Core Innovation

This is the core design bet of the swarm approach.

Public Aardvark documentation does not fully disclose internal agent topology. Regardless of Aardvark internals, any pipeline where the same reasoning loop both finds and validates issues can have **confirmation bias** risk.

Our approach introduces **adversarial tension**: two agents with opposing objectives, judged by a neutral third party.

## How It Works

```
Candidate Vulnerability
        │
        ├──────────────────────────────────┐
        v                                  v
┌───────────────────┐           ┌───────────────────┐
│    RED TEAM        │           │    BLUE TEAM       │
│                   │           │                   │
│ OBJECTIVE:        │           │ OBJECTIVE:        │
│ Prove it's real   │           │ Prove it's fake   │
│                   │           │                   │
│ INCENTIVE:        │           │ INCENTIVE:        │
│ Working exploit   │           │ Evidence of        │
│ = high score      │           │ mitigation         │
│                   │           │ = high score       │
└────────┬──────────┘           └────────┬──────────┘
         │                               │
         │ Exploit PoC                   │ Defense Evidence
         │ Attack chain                  │ Mitigations found
         │ Sandbox result               │ Unreachability proof
         │                               │
         v                               v
┌─────────────────────────────────────────────────┐
│                   JUDGE                          │
│                                                 │
│ WEIGHING RULES:                                 │
│                                                 │
│ 1. Working sandbox exploit > all theory         │
│ 2. Code-level mitigation > "probably safe"      │
│ 3. Reachability proof > assumption              │
│ 4. Both agents' confidence matters              │
│                                                 │
│ OUTPUT:                                         │
│ - Verdict: CONFIRMED / REJECTED / INCONCLUSIVE  │
│ - Severity: CRITICAL / HIGH / MEDIUM / LOW      │
│ - Confidence: 0-100                             │
│ - Reasoning trace                               │
└─────────────────────────────────────────────────┘
```

## Red Team Agent Prompt Strategy

The Red Team agent is prompted to think like an attacker:

```
You are a senior penetration tester. Your job is to PROVE that a
reported vulnerability is exploitable. You are rewarded for:
- Writing working exploit code
- Successfully executing exploits in the sandbox
- Documenting complete attack chains
- Finding the most impactful exploitation path

You are NOT rewarded for:
- Theoretical attacks that can't be demonstrated
- Over-inflating severity
- Ignoring existing protections

Given:
- Vulnerability report: {report}
- Source code: {code}
- Threat model: {threat_model}

Write a complete exploit PoC and explain each step.
```

## Blue Team Agent Prompt Strategy

The Blue Team agent is prompted to think like a defender:

```
You are a senior security engineer reviewing a vulnerability report.
Your job is to determine if this is a FALSE POSITIVE. You are
rewarded for:
- Finding existing mitigations in the codebase
- Proving the vulnerable path is unreachable
- Identifying runtime protections that block exploitation
- Providing evidence-based arguments

You are NOT rewarded for:
- Dismissing real vulnerabilities
- Hand-waving ("it's probably fine")
- Ignoring the exploit evidence

Given:
- Vulnerability report: {report}
- Source code: {code}  (full repo access)
- Threat model: {threat_model}

Analyze whether this vulnerability is actually exploitable.
Present your evidence.
```

## Judge Agent Prompt Strategy

```
You are a neutral security judge evaluating a vulnerability dispute.

RED TEAM claims this is exploitable and provides:
{red_team_evidence}

BLUE TEAM claims this is a false positive and provides:
{blue_team_evidence}

WEIGHING RULES (in order of importance):
1. A working exploit in the sandbox is the strongest evidence
2. Code-level mitigations (input validation, parameterized queries)
   are strong counter-evidence
3. Theoretical arguments are weaker than demonstrated evidence
4. Consider the threat model context

Provide your verdict:
- CONFIRMED: Vulnerability is real and exploitable
- REJECTED: This is a false positive
- INCONCLUSIVE: Need more investigation

Also provide severity (CRITICAL/HIGH/MEDIUM/LOW) and confidence (0-100).
```

## Example Scenario

### Input: SQL Injection Candidate

Scanner finds:
```python
# user_service.py:42
def search_users(query):
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    return db.execute(sql)
```

### Red Team Response
```
EXPLOIT PoC:

1. Target: GET /api/users?search=test
2. Payload: test' UNION SELECT password FROM users--
3. Full URL: /api/users?search=test' UNION SELECT password FROM users--

Sandbox execution result:
- Sent request to sandbox app
- Response contained password hashes for all users
- CONFIRMED: SQL injection allows full database extraction

Attack chain:
1. Attacker sends crafted search query
2. String interpolation inserts payload into SQL
3. UNION SELECT extracts data from any table
4. No authentication required for search endpoint

Severity: CRITICAL (full database access)
```

### Blue Team Response
```
ANALYSIS:

1. Checked for WAF/middleware: No input sanitization middleware found
2. Checked for ORM: Direct SQL execution, no ORM protection
3. Checked for parameterized queries: NOT USED (string formatting)
4. Checked authentication: Search endpoint is PUBLIC
5. Checked rate limiting: None on search endpoint

VERDICT: I cannot find any mitigations. The Red Team's exploit
appears valid. The f-string SQL construction is directly vulnerable.

However, I note:
- Database permissions should be checked (read-only user?)
- Network exposure should be verified (is this internal-only?)

Confidence that this is a FALSE POSITIVE: 5%
```

### Judge Verdict
```
VERDICT: CONFIRMED

REASONING:
- Red Team provided a WORKING exploit with database extraction
- Blue Team could not find any mitigations
- Blue Team's own confidence in false positive is only 5%
- The vulnerable code path is publicly accessible
- No input validation, parameterization, or ORM protection exists

SEVERITY: CRITICAL
- Unauthenticated access
- Full database extraction possible
- Public endpoint

CONFIDENCE: 97/100
```

## Why This May Beat Single-Loop Validation

| Scenario | Single-Loop Validation | Adversarial Swarm |
|----------|------------------------|-------------------|
| Real vuln, obvious | Catches it | Catches it (both agree) |
| Real vuln, subtle | Might miss mitigations | Red Team finds it, Blue Team confirms no mitigation |
| False positive, obvious | Might still flag it | Blue Team provides evidence, Judge rejects |
| False positive, subtle | Often flags it (noise) | Blue Team finds hidden mitigation, Judge considers |
| Vuln with partial mitigation | Binary yes/no | Nuanced: "exploitable only if X condition" |
| Edge case / uncertain | Over/under reports | INCONCLUSIVE verdict triggers deeper analysis |

## Metrics

Track these to tune the system:

- **Red Team win rate**: % of candidates confirmed as real
- **Blue Team win rate**: % of candidates rejected as false positive
- **Judge override rate**: How often Judge disagrees with majority evidence
- **Actual false positive rate**: Confirmed by human review
- **Actual false negative rate**: Vulns missed entirely (found by external audit)
