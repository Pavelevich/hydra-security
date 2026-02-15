export type SandboxProfile = "generic" | "solana";

export interface SandboxConfig {
  profile: SandboxProfile;
  timeoutMs: number;
  memoryLimitMb: number;
  cpuLimit: number;
}

export interface SandboxContainer {
  id: string;
  profile: SandboxProfile;
  created_at: string;
}

export interface ExecResult {
  exit_code: number;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  duration_ms: number;
}

export interface SandboxSession {
  container: SandboxContainer;
  exec(command: string[], timeoutMs?: number): Promise<ExecResult>;
  copyIn(hostPath: string, containerPath: string): Promise<void>;
  writeFile(containerPath: string, content: string): Promise<void>;
  destroy(): Promise<void>;
}

export const DEFAULT_SANDBOX_CONFIG: Record<SandboxProfile, SandboxConfig> = {
  generic: {
    profile: "generic",
    timeoutMs: 60_000,
    memoryLimitMb: 512,
    cpuLimit: 1.0
  },
  solana: {
    profile: "solana",
    timeoutMs: 120_000,
    memoryLimitMb: 2048,
    cpuLimit: 2.0
  }
};
