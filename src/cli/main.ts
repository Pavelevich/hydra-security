import { promises as fs } from "node:fs";
import path from "node:path";
import { runFullScan } from "../orchestrator/run-scan";
import { toMarkdownReport } from "../output/report";
import { toSarif } from "../output/sarif";

function usage(): string {
  return [
    "Hydra Security CLI",
    "",
    "Usage:",
    "  bun run src/cli/main.ts scan [targetPath] [--json] [--sarif path]",
    "  bun run src/cli/main.ts help",
    "",
    "Examples:",
    "  bun run src/cli/main.ts scan .",
    "  bun run src/cli/main.ts scan ./golden_repos/solana_seeded_v1/repo-template-a --json",
    "  bun run src/cli/main.ts scan . --sarif out.sarif.json"
  ].join("\n");
}

async function handleScan(args: string[]): Promise<void> {
  const maybePath = args.find((arg) => !arg.startsWith("--")) ?? ".";
  const asJson = args.includes("--json");
  const sarifFlagIndex = args.findIndex((arg) => arg === "--sarif");
  const sarifPath = sarifFlagIndex >= 0 ? args[sarifFlagIndex + 1] : undefined;

  const result = await runFullScan(maybePath);

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
