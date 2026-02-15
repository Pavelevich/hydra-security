import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import type {
  ExecResult,
  SandboxConfig,
  SandboxContainer,
  SandboxProfile,
  SandboxSession
} from "./types";
import { DEFAULT_SANDBOX_CONFIG } from "./types";

const IMAGE_MAP: Record<SandboxProfile, string> = {
  generic: "hydra/sandbox-generic:local",
  solana: "hydra/sandbox-solana:local"
};

function runDocker(args: string[], timeoutMs: number): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const child = execFile("docker", args, { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error && "killed" in error && error.killed) {
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "", exitCode: -1 });
        return;
      }
      const exitCode = error && "code" in error ? (error.code as number) ?? 1 : 0;
      resolve({ stdout: stdout ?? "", stderr: stderr ?? "", exitCode });
    });

    child.on("error", reject);
  });
}

async function dockerExec(
  containerId: string,
  command: string[],
  timeoutMs: number
): Promise<ExecResult> {
  const startMs = Date.now();
  const result = await runDocker(
    ["exec", containerId, ...command],
    timeoutMs
  );
  const durationMs = Date.now() - startMs;
  const timedOut = result.exitCode === -1;

  return {
    exit_code: timedOut ? 124 : result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    timed_out: timedOut,
    duration_ms: durationMs
  };
}

export async function createSandbox(
  profile: SandboxProfile,
  configOverrides?: Partial<SandboxConfig>
): Promise<SandboxSession> {
  const config = { ...DEFAULT_SANDBOX_CONFIG[profile], ...configOverrides };
  const image = IMAGE_MAP[profile];
  const containerName = `hydra-sandbox-${profile}-${randomUUID().slice(0, 8)}`;

  const createArgs = [
    "run", "-d",
    "--name", containerName,
    "--read-only",
    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
    "--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=256m",
    "--security-opt", "no-new-privileges:true",
    "--cap-drop", "ALL",
    "--network", "none",
    "--pids-limit", "256",
    "--memory", `${config.memoryLimitMb}m`,
    "--cpus", String(config.cpuLimit),
    image,
    "sleep", "infinity"
  ];

  const createResult = await runDocker(createArgs, 30_000);
  if (createResult.exitCode !== 0) {
    throw new Error(`Failed to create sandbox container: ${createResult.stderr}`);
  }

  const containerId = createResult.stdout.trim().slice(0, 12);
  const container: SandboxContainer = {
    id: containerId,
    profile,
    created_at: new Date().toISOString()
  };

  const session: SandboxSession = {
    container,

    async exec(command: string[], timeoutMs?: number): Promise<ExecResult> {
      return dockerExec(containerId, command, timeoutMs ?? config.timeoutMs);
    },

    async copyIn(hostPath: string, containerPath: string): Promise<void> {
      const result = await runDocker(
        ["cp", hostPath, `${containerId}:${containerPath}`],
        30_000
      );
      if (result.exitCode !== 0) {
        throw new Error(`Failed to copy into sandbox: ${result.stderr}`);
      }
    },

    async writeFile(containerPath: string, content: string): Promise<void> {
      const result = await runDocker(
        ["exec", "-i", containerId, "sh", "-c", `cat > ${containerPath}`],
        10_000
      );
      // For writeFile we need stdin, use a different approach
      await new Promise<void>((resolve, reject) => {
        const child = execFile(
          "docker",
          ["exec", "-i", containerId, "sh", "-c", `cat > ${containerPath}`],
          { timeout: 10_000 },
          (error) => {
            if (error) reject(new Error(`writeFile failed: ${error.message}`));
            else resolve();
          }
        );
        child.stdin?.write(content);
        child.stdin?.end();
      });
    },

    async destroy(): Promise<void> {
      await runDocker(["rm", "-f", containerName], 15_000);
    }
  };

  return session;
}

export async function isSandboxAvailable(): Promise<boolean> {
  try {
    const result = await runDocker(["info", "--format", "{{.ServerVersion}}"], 5_000);
    return result.exitCode === 0;
  } catch {
    return false;
  }
}

export async function isSandboxImageBuilt(profile: SandboxProfile): Promise<boolean> {
  const image = IMAGE_MAP[profile];
  try {
    const result = await runDocker(["image", "inspect", image], 5_000);
    return result.exitCode === 0;
  } catch {
    return false;
  }
}
