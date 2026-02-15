import { execFile } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface GitDiffOptions {
  baseRef?: string;
  headRef?: string;
  includeUntracked?: boolean;
}

export interface ResolvedDiffSelection {
  baseRef?: string;
  headRef?: string;
  changedFiles: string[];
}

function parseLines(stdout: string): string[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

async function runGit(rootPath: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", rootPath, ...args], {
      maxBuffer: 8 * 1024 * 1024
    });
    return stdout;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown git error";
    throw new Error(`git command failed (${args.join(" ")}): ${detail}`);
  }
}

async function toExistingAbsolutePaths(rootPath: string, filePaths: string[]): Promise<string[]> {
  const out: string[] = [];
  for (const filePath of filePaths) {
    const absolutePath = path.resolve(rootPath, filePath);
    try {
      const stat = await fs.stat(absolutePath);
      if (stat.isFile()) {
        out.push(absolutePath);
      }
    } catch {
      // Ignore deleted or unreachable paths in diff output.
    }
  }
  return out;
}

export async function resolveDiffSelection(
  rootPath: string,
  options: GitDiffOptions = {}
): Promise<ResolvedDiffSelection> {
  const baseRef = options.baseRef?.trim() || undefined;
  const headRef = options.headRef?.trim() || undefined;
  if (!baseRef && headRef) {
    throw new Error("headRef requires baseRef");
  }

  const includeUntracked = options.includeUntracked ?? true;
  const trackedArgs = baseRef
    ? ["diff", "--name-only", "--diff-filter=ACMR", `${baseRef}..${headRef ?? "HEAD"}`]
    : ["diff", "--name-only", "--diff-filter=ACMR", "HEAD"];

  const tracked = parseLines(await runGit(rootPath, trackedArgs));
  const untracked = includeUntracked
    ? parseLines(await runGit(rootPath, ["ls-files", "--others", "--exclude-standard"]))
    : [];

  const unique = [...new Set([...tracked, ...untracked])];
  const existingAbsolutePaths = await toExistingAbsolutePaths(rootPath, unique);

  return {
    baseRef,
    headRef: headRef ?? (baseRef ? "HEAD" : undefined),
    changedFiles: existingAbsolutePaths
  };
}
