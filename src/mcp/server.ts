import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";
import path from "node:path";
import { spawn } from "node:child_process";
import { runFullScan, runDiffScan } from "../orchestrator/run-scan.js";
import { toMarkdownReport } from "../output/report.js";
import { toSarif } from "../output/sarif.js";
import type { ScanResult } from "../types.js";

const PROJECT_ROOT = path.resolve(import.meta.dirname, "../..");

const server = new McpServer({
  name: "hydra-security",
  version: "0.1.0",
});

// --- Tool 1: hydra_scan ---
server.registerTool(
  "hydra_scan",
  {
    description:
      "Run a full Hydra security scan on a Solana/Anchor repository. Returns a markdown report with all findings.",
    inputSchema: {
      target_path: z
        .string()
        .describe("Absolute or relative path to the repository to scan"),
    },
  },
  async ({ target_path }) => {
    const resolved = path.isAbsolute(target_path)
      ? target_path
      : path.resolve(PROJECT_ROOT, target_path);

    try {
      const result = await runFullScan(resolved);
      const report = toMarkdownReport(result);
      const summary = `Found ${result.findings.length} finding(s) across ${result.agent_runs?.length ?? 0} agent runs.`;

      return {
        content: [
          { type: "text" as const, text: summary },
          { type: "text" as const, text: report },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Scan failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 2: hydra_diff_scan ---
server.registerTool(
  "hydra_diff_scan",
  {
    description:
      "Run a differential Hydra security scan on only the files changed since a git reference.",
    inputSchema: {
      target_path: z
        .string()
        .describe("Absolute or relative path to the repository"),
      base_ref: z
        .string()
        .optional()
        .describe("Git base reference (e.g. 'origin/main', 'HEAD~3')"),
      head_ref: z
        .string()
        .optional()
        .describe("Git head reference (defaults to working directory)"),
    },
  },
  async ({ target_path, base_ref, head_ref }) => {
    const resolved = path.isAbsolute(target_path)
      ? target_path
      : path.resolve(PROJECT_ROOT, target_path);

    try {
      const result = await runDiffScan(resolved, { baseRef: base_ref, headRef: head_ref });
      const report = toMarkdownReport(result);
      const changedCount = result.target.diff?.changed_files?.length ?? 0;
      const summary = `Diff scan: ${changedCount} changed file(s), ${result.findings.length} finding(s).`;

      return {
        content: [
          { type: "text" as const, text: summary },
          { type: "text" as const, text: report },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Diff scan failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 3: hydra_report_sarif ---
server.registerTool(
  "hydra_report_sarif",
  {
    description:
      "Convert a Hydra scan result JSON into SARIF 2.1.0 format for GitHub Security tab or IDE integration.",
    inputSchema: {
      scan_result_json: z
        .string()
        .describe("JSON string of a ScanResult object (from a previous hydra_scan call)"),
    },
  },
  async ({ scan_result_json }) => {
    try {
      const result = JSON.parse(scan_result_json) as ScanResult;
      const sarif = toSarif(result);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(sarif, null, 2) },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `SARIF conversion failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 4: hydra_eval ---
function runBunScript(script: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("bun", ["run", script], {
      cwd: PROJECT_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (data: Buffer) => { stdout += data.toString(); });
    child.stderr.on("data", (data: Buffer) => { stderr += data.toString(); });
    child.on("close", (code) => {
      if (code === 0) {
        resolve(stdout || stderr);
      } else {
        reject(new Error(`Script '${script}' exited with code ${code}:\n${stderr || stdout}`));
      }
    });
    child.on("error", reject);
  });
}

server.registerTool(
  "hydra_eval",
  {
    description:
      "Run the Hydra evaluation suite against benchmark datasets. Compares Hydra vs baselines and reports precision/recall metrics.",
    inputSchema: {
      dataset: z
        .enum(["d1", "d2", "d3", "d4", "core", "all"])
        .describe(
          "Dataset to evaluate: d1/d2 (seeded), d3 (clean controls), d4 (holdout), core (d1+d2), all (d1-d4)"
        ),
    },
  },
  async ({ dataset }) => {
    const scriptMap: Record<string, string> = {
      d1: "eval:d1",
      d2: "eval:d2",
      d3: "eval:d3",
      d4: "eval:d4",
      core: "eval:core",
      all: "eval:phase0",
    };

    const script = scriptMap[dataset];
    try {
      const output = await runBunScript(script);
      return {
        content: [{ type: "text" as const, text: output }],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Evaluation failed: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- Tool 5: hydra_list_scanners ---
server.registerTool(
  "hydra_list_scanners",
  {
    description:
      "List all available Hydra security scanners and the vulnerability classes they detect.",
  },
  async () => {
    const scanners = [
      {
        id: "scanner.solana.account-validation",
        vuln_classes: ["missing_signer_check", "missing_has_one", "account_type_confusion"],
        description: "Detects missing signer checks, relationship constraints, and account type confusion in Solana/Anchor programs.",
      },
      {
        id: "scanner.solana.cpi",
        vuln_classes: ["arbitrary_cpi", "cpi_signer_seed_bypass", "cpi_reentrancy"],
        description: "Detects unsafe cross-program invocation patterns including arbitrary CPI targets and reentrancy.",
      },
      {
        id: "scanner.solana.pda",
        vuln_classes: ["non_canonical_bump", "seed_collision", "attacker_controlled_seed"],
        description: "Detects PDA derivation issues including non-canonical bumps and attacker-controlled seeds.",
      },
      {
        id: "signal.deterministic.adapters",
        vuln_classes: [],
        description: "Rule-based deterministic signal detection (lint-level checks).",
      },
    ];

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(scanners, null, 2),
        },
      ],
    };
  }
);

// --- Start server ---
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Hydra Security MCP server running on stdio");
}

main().catch((err) => {
  console.error("MCP server error:", err);
  process.exit(1);
});
