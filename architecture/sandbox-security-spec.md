# Sandbox Security Specification

## Purpose

Define hard security requirements for exploit-validation sandboxes used by Red Team agents.

Goal:
- Allow reproducible exploit execution while minimizing host and data risk.

## Threat Model

Assume exploit code can be malicious and attempts:
- Container breakout
- Host filesystem access
- Network exfiltration
- Privilege escalation
- Denial of service

## Security Requirements

### 1. Isolation Boundary

- Run every exploit in an ephemeral container.
- Use non-root user inside container.
- Disable privileged mode.
- Drop all Linux capabilities unless explicitly required.
- Apply seccomp profile with deny-by-default posture for risky syscalls.
- Apply AppArmor/SELinux profile where available.

### 2. Filesystem Controls

- Root filesystem must be read-only.
- Use `tmpfs` for writable runtime paths (`/tmp`, working dir).
- No host path mounts by default.
- If mounts are needed, mount read-only and scope to minimum required files.
- Remove container and writable layers after run completion.

### 3. Network Controls

- Default network mode: no outbound network.
- If egress is required for a specific test, use explicit allowlist and log policy exceptions.
- Block metadata service and local host bridge access.

### 4. Resource Controls

- Hard limits for CPU, memory, pids, and wall time.
- Kill container on timeout or limit breach.
- Enforce max artifact size for logs and outputs.

### 5. Secrets and Credentials

- No production secrets available in sandbox.
- Use synthetic test credentials only.
- Inject credentials only per run and destroy immediately after execution.

### 6. Execution Policy

- Only execute generated code after static safety checks.
- Disallow shell escape patterns where feasible.
- Record command line and entrypoint for every run.

### 7. Artifact Handling

- Capture stdout/stderr, exit code, and minimal execution traces.
- Sanitize artifacts before persistence (remove secrets/tokens/paths).
- Store artifacts with immutable run IDs.

### 8. Audit Logging

Log at minimum:
- Run ID, timestamp, scanner/agent ID
- Container image digest
- Resource limits applied
- Network mode
- Exit status and termination reason
- Hashes of produced artifacts

### 9. Solana-Specific Sandbox Mode

- Use local `solana-test-validator` only.
- No mainnet/devnet keys in runtime.
- Reset validator state per exploit run.
- Keep validator RPC bound to local sandbox network namespace only.

### 10. Incident Handling

On suspected escape or policy breach:
1. Stop all active sandboxes.
2. Preserve forensic logs and artifacts.
3. Rotate any potentially exposed credentials.
4. Block further runs until root cause review completes.

## Verification Checklist

Before production use, verify:
- [ ] Non-root enforced
- [ ] Privileged mode disabled
- [ ] Capabilities minimized
- [ ] Seccomp/AppArmor profiles active
- [ ] Read-only rootfs active
- [ ] No-network default active
- [ ] CPU/memory/pids/timeouts enforced
- [ ] Artifacts sanitized and immutable
- [ ] Solana validator isolation verified
- [ ] Incident runbook tested

## Non-Goals (V1)

- Full VM-level isolation for every run
- Multi-tenant untrusted public execution
- Internet-connected exploit execution by default
