# Sandbox Docker Setup

This directory provides hardened Docker sandbox scaffolding for Hydra exploit validation.

## Files

- `docker/sandbox/Dockerfile.generic`: generic exploit sandbox runtime
- `docker/sandbox/Dockerfile.solana`: Solana runtime for `solana-test-validator` workflows
- `docker/docker-compose.yml`: sandbox service definitions and hardening defaults

## Security Defaults

The compose services apply V1 sandbox controls by default:

- non-root user
- `read_only: true`
- `tmpfs` writable paths only
- `cap_drop: [ALL]`
- `no-new-privileges`
- `network_mode: none` (or shared namespace with `solana-validator`)
- `pids_limit`, memory, and cpu limits

Notes:
- No host mounts are defined by default.
- Containers are intended to be ephemeral (`run --rm`).

## Usage

Build images:

```bash
docker compose -f docker/docker-compose.yml --profile generic build
docker compose -f docker/docker-compose.yml --profile solana build
```

Run a generic isolated shell:

```bash
docker compose -f docker/docker-compose.yml --profile generic run --rm generic sh
```

Run Solana validator sandbox:

```bash
docker compose -f docker/docker-compose.yml --profile solana up -d solana-validator
docker compose -f docker/docker-compose.yml --profile solana run --rm solana-runner solana -u http://127.0.0.1:8899 cluster-version
docker compose -f docker/docker-compose.yml --profile solana down --remove-orphans
```

## Solana Isolation Mode

- Validator binds to `127.0.0.1` only.
- `solana-runner` shares the validator namespace (`network_mode: service:solana-validator`) to keep RPC local to the sandbox namespace.
- No host port publishing is configured.
