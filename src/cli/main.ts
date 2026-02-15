import { promises as fs } from "node:fs";
import path from "node:path";
import { runDiffScan, runFullScan } from "../orchestrator/run-scan";
import { startOrchestratorDaemon } from "../orchestrator/daemon";
import { toMarkdownReport } from "../output/report";
import { toSarif } from "../output/sarif";
import { startGitHubApp } from "../integrations/github-app";
import type { ScanResult } from "../types";

const CONFIG_FILE_NAME = ".hydra.json";

interface HydraConfig {
  scanners?: string[];
  min_confidence?: number;
  min_severity?: string;
  sarif_output?: string;
  slack_webhook?: string;
  discord_webhook?: string;
  github_app?: {
    webhook_secret?: string;
    app_id?: string;
    private_key_path?: string;
    port?: number;
  };
}

function usage(): string {
  return [
    "Hydra Security CLI",
    "",
    "Usage:",
    "  hydra-audit scan [targetPath] [--mode full|diff] [--base-ref ref] [--head-ref ref] [--json] [--sarif path]",
    "  hydra-audit diff [targetPath] [--base-ref ref] [--head-ref ref] [--json] [--sarif path]",
    "  hydra-audit report <scan-result.json> [--format markdown|json|sarif] [--output path]",
    "  hydra-audit config [--show] [--set key=value] [--init]",
    "  hydra-audit daemon [--host 127.0.0.1] [--port 8787]",
    "  hydra-audit github-app [--port 3000]",
    "  hydra-audit help",
    "",
    "Commands:",
    "  scan       Run a full or differential security scan",
    "  diff       Shorthand for 'scan --mode diff'",
    "  report     Generate a report from a saved scan result JSON",
    "  config     Show or modify scanner configuration",
    "  daemon     Start the orchestrator HTTP daemon",
    "  github-app Start the GitHub App webhook listener",
    "",
    "Examples:",
    "  hydra-audit scan .",
    "  hydra-audit scan . --mode diff --base-ref origin/main",
    "  hydra-audit scan . --sarif out.sarif.json",
    "  hydra-audit diff . --base-ref HEAD~3 --json",
    "  hydra-audit report scan-result.json --format sarif --output report.sarif.json",
    "  hydra-audit config --show",
    "  hydra-audit config --init",
    "  hydra-audit config --set min_confidence=60",
    "  hydra-audit daemon --port 8787",
    "  hydra-audit github-app --port 3000"
  ].join("\n");
}

function getOptionValue(args: string[], flag: string): string | undefined {
  const idx = args.findIndex((arg) => arg === flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

async function handleScan(args: string[]): Promise<void> {
  const maybePath = args.find((arg) => !arg.startsWith("--")) ?? ".";
  const mode = getOptionValue(args, "--mode") ?? "full";
  if (mode !== "full" && mode !== "diff") {
    throw new Error(`Invalid --mode value: ${mode}. Expected full or diff.`);
  }
  const baseRef = getOptionValue(args, "--base-ref");
  const headRef = getOptionValue(args, "--head-ref");
  if (headRef && !baseRef) {
    throw new Error("--head-ref requires --base-ref.");
  }
  const asJson = args.includes("--json");
  const sarifFlagIndex = args.findIndex((arg) => arg === "--sarif");
  const sarifPath = sarifFlagIndex >= 0 ? args[sarifFlagIndex + 1] : undefined;

  const adversarial = args.includes("--adversarial");
  const patch = args.includes("--patch");

  const result =
    mode === "diff"
      ? await runDiffScan(maybePath, { baseRef, headRef, adversarial, patch })
      : await runFullScan(maybePath, { adversarial, patch });

  if (asJson) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(toMarkdownReport(result));
  }

  if (sarifPath) {
    const outputPath = path.resolve(sarifPath);
    await fs.writeFile(outputPath, JSON.stringify(toSarif(result), null, 2), "utf8");
    console.log(`\nSARIF written to: ${outputPath}`);
  }
}

async function handleDiff(args: string[]): Promise<void> {
  // `diff` is just `scan --mode diff`
  await handleScan(["--mode", "diff", ...args]);
}

async function handleReport(args: string[]): Promise<void> {
  const inputPath = args.find((arg) => !arg.startsWith("--"));
  if (!inputPath) {
    console.error("Error: report requires a scan result JSON file path.");
    console.error("Usage: hydra-audit report <scan-result.json> [--format markdown|json|sarif] [--output path]");
    process.exitCode = 1;
    return;
  }

  const resolvedPath = path.resolve(inputPath);
  let raw: string;
  try {
    raw = await fs.readFile(resolvedPath, "utf8");
  } catch {
    console.error(`Error: could not read file: ${resolvedPath}`);
    process.exitCode = 1;
    return;
  }

  let result: ScanResult;
  try {
    result = JSON.parse(raw) as ScanResult;
  } catch {
    console.error(`Error: invalid JSON in ${resolvedPath}`);
    process.exitCode = 1;
    return;
  }

  const format = getOptionValue(args, "--format") ?? "markdown";
  const outputPath = getOptionValue(args, "--output");

  let output: string;
  switch (format) {
    case "markdown":
      output = toMarkdownReport(result);
      break;
    case "json":
      output = JSON.stringify(result, null, 2);
      break;
    case "sarif":
      output = JSON.stringify(toSarif(result), null, 2);
      break;
    default:
      console.error(`Invalid --format value: ${format}. Expected markdown, json, or sarif.`);
      process.exitCode = 1;
      return;
  }

  if (outputPath) {
    await fs.writeFile(path.resolve(outputPath), output, "utf8");
    console.log(`Report written to: ${path.resolve(outputPath)}`);
  } else {
    console.log(output);
  }
}

async function loadConfig(dir?: string): Promise<{ config: HydraConfig; configPath: string }> {
  const searchDir = dir ?? process.cwd();
  const configPath = path.join(searchDir, CONFIG_FILE_NAME);
  try {
    const raw = await fs.readFile(configPath, "utf8");
    return { config: JSON.parse(raw) as HydraConfig, configPath };
  } catch {
    return { config: {}, configPath };
  }
}

async function handleConfig(args: string[]): Promise<void> {
  if (args.includes("--init")) {
    const configPath = path.join(process.cwd(), CONFIG_FILE_NAME);
    try {
      await fs.access(configPath);
      console.log(`Config already exists: ${configPath}`);
      return;
    } catch {
      // File doesn't exist — create default
    }

    const defaultConfig: HydraConfig = {
      scanners: ["account-validation", "cpi-security", "pda-security"],
      min_confidence: 50,
      min_severity: "LOW"
    };

    await fs.writeFile(configPath, JSON.stringify(defaultConfig, null, 2) + "\n", "utf8");
    console.log(`Created: ${configPath}`);
    return;
  }

  const { config, configPath } = await loadConfig();

  if (args.includes("--show") || args.length === 0) {
    console.log(`Config: ${configPath}`);
    console.log(JSON.stringify(config, null, 2));
    return;
  }

  const setValues = args
    .filter((arg) => arg.startsWith("--set"))
    .map(() => {
      const setIndex = args.indexOf("--set");
      return setIndex >= 0 ? args[setIndex + 1] : undefined;
    })
    .filter((v): v is string => v !== undefined);

  // Also handle inline --set key=value
  for (const arg of args) {
    if (!arg.startsWith("--")) {
      const eqIndex = arg.indexOf("=");
      if (eqIndex > 0) {
        setValues.push(arg);
      }
    }
  }

  const setValueFromFlag = getOptionValue(args, "--set");
  if (setValueFromFlag && !setValues.includes(setValueFromFlag)) {
    setValues.push(setValueFromFlag);
  }

  if (setValues.length === 0) {
    console.log(`Config: ${configPath}`);
    console.log(JSON.stringify(config, null, 2));
    return;
  }

  const updated = { ...config } as Record<string, unknown>;
  for (const kv of setValues) {
    const eqIndex = kv.indexOf("=");
    if (eqIndex <= 0) {
      console.error(`Invalid --set format: ${kv}. Expected key=value.`);
      process.exitCode = 1;
      return;
    }
    const key = kv.slice(0, eqIndex);
    const value = kv.slice(eqIndex + 1);

    // Parse numeric values
    const numValue = Number(value);
    if (!Number.isNaN(numValue) && value.trim() !== "") {
      updated[key] = numValue;
    } else if (value === "true") {
      updated[key] = true;
    } else if (value === "false") {
      updated[key] = false;
    } else if (value.includes(",")) {
      updated[key] = value.split(",").map((s) => s.trim());
    } else {
      updated[key] = value;
    }
  }

  await fs.writeFile(configPath, JSON.stringify(updated, null, 2) + "\n", "utf8");
  console.log(`Updated: ${configPath}`);
  console.log(JSON.stringify(updated, null, 2));
}

async function handleGitHubApp(args: string[]): Promise<void> {
  const port = Number(getOptionValue(args, "--port") ?? "3000");
  const host = getOptionValue(args, "--host") ?? "127.0.0.1";

  const webhookSecret = process.env.HYDRA_GITHUB_WEBHOOK_SECRET;
  const appId = process.env.HYDRA_GITHUB_APP_ID;
  const privateKey = process.env.HYDRA_GITHUB_PRIVATE_KEY;

  if (!webhookSecret || !appId || !privateKey) {
    console.error("Error: GitHub App requires environment variables:");
    console.error("  HYDRA_GITHUB_WEBHOOK_SECRET");
    console.error("  HYDRA_GITHUB_APP_ID");
    console.error("  HYDRA_GITHUB_PRIVATE_KEY");
    process.exitCode = 1;
    return;
  }

  startGitHubApp(
    { webhookSecret, appId, privateKey, host, port },
    async (repoFullName: string) => {
      // Default resolver: assume repos are cloned under ./repos/<owner>/<name>
      const reposDir = process.env.HYDRA_REPOS_DIR ?? path.join(process.cwd(), "repos");
      const repoPath = path.join(reposDir, repoFullName);
      await fs.access(repoPath);
      return repoPath;
    }
  );
}

async function main(): Promise<void> {
  const [, , command, ...args] = process.argv;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    console.log(usage());
    return;
  }

  switch (command) {
    case "scan":
      await handleScan(args);
      return;
    case "diff":
      await handleDiff(args);
      return;
    case "report":
      await handleReport(args);
      return;
    case "config":
      await handleConfig(args);
      return;
    case "daemon": {
      const host = getOptionValue(args, "--host") ?? "127.0.0.1";
      const portRaw = getOptionValue(args, "--port") ?? "8787";
      const port = Number(portRaw);
      if (!Number.isInteger(port) || port <= 0 || port > 65535) {
        console.error(`Invalid --port value: ${portRaw}`);
        process.exitCode = 1;
        return;
      }
      startOrchestratorDaemon({ host, port });
      return;
    }
    case "github-app":
      await handleGitHubApp(args);
      return;
    default:
      console.error(`Unknown command: ${command}`);
      console.log("");
      console.log(usage());
      process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error("CLI error:", error);
  process.exitCode = 1;
});
