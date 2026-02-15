import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import type { Dirent } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type {
  ScanTarget,
  ThreatModelFingerprint,
  ThreatModelInfo,
  ThreatModelSummary,
  ThreatModelVersion
} from "../types";

const execFileAsync = promisify(execFile);

const THREAT_MODEL_SCHEMA_VERSION = "1.0.0";
const MAX_SOURCE_FILES = 2000;
const MAX_SCOPE_FILES = 50;
const MAX_ENTRY_POINTS = 24;
const MAX_BUFFER_BYTES = 8 * 1024 * 1024;

const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const STORE_ROOT = path.join(PROJECT_ROOT, ".hydra", "threat-models");

const IGNORED_DIR_NAMES = new Set([
  ".git",
  ".idea",
  ".vscode",
  ".hydra",
  "node_modules",
  "target",
  "dist",
  "build",
  "coverage"
]);

const SOURCE_EXTENSIONS = new Set([".rs", ".ts", ".tsx", ".js", ".jsx", ".py", ".sol", ".go"]);

const EXTENSION_TO_LANGUAGE: Record<string, string> = {
  ".rs": "rust",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".py": "python",
  ".sol": "solidity",
  ".go": "go"
};

interface ThreatModelStore {
  schema_version: string;
  repo_id: string;
  repo_root: string;
  latest_version_id?: string;
  by_fingerprint: Record<string, string>;
  versions: ThreatModelVersion[];
}

interface GitContext {
  git_commit?: string;
  git_tree?: string;
  git_is_dirty: boolean;
}

function toPosixPath(value: string): string {
  return value.replaceAll("\\", "/");
}

function digest(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function repoIdFor(rootPath: string): string {
  return digest(path.resolve(rootPath)).slice(0, 16);
}

function normalizeRelPath(rootPath: string, filePath: string): string {
  const absolutePath = path.isAbsolute(filePath) ? filePath : path.resolve(rootPath, filePath);
  return toPosixPath(path.relative(rootPath, absolutePath));
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function runGit(rootPath: string, args: string[]): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync("git", ["-C", rootPath, ...args], {
      maxBuffer: MAX_BUFFER_BYTES
    });
    return stdout.trim();
  } catch {
    return undefined;
  }
}

async function getGitContext(rootPath: string): Promise<GitContext> {
  const gitCommit = await runGit(rootPath, ["rev-parse", "HEAD"]);
  const gitTree = await runGit(rootPath, ["rev-parse", "HEAD^{tree}"]);
  const gitStatus = await runGit(rootPath, ["status", "--porcelain"]);
  return {
    git_commit: gitCommit || undefined,
    git_tree: gitTree || undefined,
    git_is_dirty: Boolean(gitStatus && gitStatus.length > 0)
  };
}

function buildFingerprint(target: ScanTarget, git: GitContext): ThreatModelFingerprint {
  const changedFiles = target.diff?.changed_files
    ? uniqueSorted(target.diff.changed_files.map((filePath) => normalizeRelPath(target.root_path, filePath)))
    : [];

  return {
    scan_mode: target.mode,
    git_commit: git.git_commit,
    git_tree: git.git_tree,
    git_is_dirty: git.git_is_dirty,
    base_ref: target.diff?.base_ref,
    head_ref: target.diff?.head_ref,
    changed_files_hash: digest(changedFiles.join("|"))
  };
}

async function listSourceFiles(rootPath: string): Promise<string[]> {
  const sourceFiles: string[] = [];
  const queue = [rootPath];

  while (queue.length > 0 && sourceFiles.length < MAX_SOURCE_FILES) {
    const currentDir = queue.shift()!;
    let entries: Dirent[];
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORED_DIR_NAMES.has(entry.name)) {
          queue.push(fullPath);
        }
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) {
        sourceFiles.push(fullPath);
        if (sourceFiles.length >= MAX_SOURCE_FILES) {
          break;
        }
      }
    }
  }

  return sourceFiles;
}

function detectLanguageBreakdown(sourceFiles: string[]): Record<string, number> {
  const breakdown: Record<string, number> = {};
  for (const filePath of sourceFiles) {
    const language = EXTENSION_TO_LANGUAGE[path.extname(filePath)] ?? "unknown";
    breakdown[language] = (breakdown[language] ?? 0) + 1;
  }
  return breakdown;
}

async function detectFrameworks(rootPath: string, sourceFiles: string[]): Promise<string[]> {
  const frameworks = new Set<string>();
  if (await fileExists(path.join(rootPath, "Anchor.toml"))) {
    frameworks.add("solana-anchor");
  }
  if (await fileExists(path.join(rootPath, "Cargo.toml"))) {
    frameworks.add("rust-cargo");
  }
  if (await fileExists(path.join(rootPath, "package.json"))) {
    frameworks.add("nodejs");
  }
  if (await fileExists(path.join(rootPath, "tsconfig.json"))) {
    frameworks.add("typescript");
  }

  const hasRust = sourceFiles.some((filePath) => filePath.endsWith(".rs"));
  const hasTsOrJs = sourceFiles.some(
    (filePath) =>
      filePath.endsWith(".ts") ||
      filePath.endsWith(".tsx") ||
      filePath.endsWith(".js") ||
      filePath.endsWith(".jsx")
  );

  if (hasRust && !frameworks.has("rust-cargo")) {
    frameworks.add("rust");
  }
  if (hasTsOrJs && !frameworks.has("nodejs")) {
    frameworks.add("javascript-runtime");
  }

  return uniqueSorted([...frameworks]);
}

async function detectEntryPoints(rootPath: string, sourceFiles: string[]): Promise<string[]> {
  const relFiles = sourceFiles.map((filePath) => normalizeRelPath(rootPath, filePath));
  const nameHeuristic = relFiles.filter((filePath) => {
    const base = path.basename(filePath);
    return base === "main.rs" || base === "lib.rs" || base === "main.ts" || base === "index.ts";
  });

  const functionHeuristic: string[] = [];
  const rustFiles = sourceFiles.filter((filePath) => filePath.endsWith(".rs")).slice(0, 30);
  for (const filePath of rustFiles) {
    let content: string;
    try {
      content = await fs.readFile(filePath, "utf8");
    } catch {
      continue;
    }

    const relPath = normalizeRelPath(rootPath, filePath);
    for (const match of content.matchAll(/\bpub\s+fn\s+([a-zA-Z0-9_]+)\s*\(/g)) {
      functionHeuristic.push(`${relPath}::${match[1]}`);
      if (functionHeuristic.length >= MAX_ENTRY_POINTS) {
        break;
      }
    }
    if (functionHeuristic.length >= MAX_ENTRY_POINTS) {
      break;
    }
  }

  return uniqueSorted([...nameHeuristic, ...functionHeuristic]).slice(0, MAX_ENTRY_POINTS);
}

function buildAssets(frameworks: string[]): string[] {
  const assets = new Set<string>(["Source code integrity", "Deployment artifacts", "Build secrets"]);

  if (frameworks.includes("solana-anchor")) {
    assets.add("Program-owned state accounts");
    assets.add("PDA authority relationships");
    assets.add("CPI permission boundaries");
    assets.add("Token custody and transfer invariants");
  }

  if (frameworks.includes("nodejs") || frameworks.includes("javascript-runtime")) {
    assets.add("API authentication state");
    assets.add("Runtime configuration and environment variables");
  }

  return uniqueSorted([...assets]);
}

function buildTrustBoundaries(frameworks: string[]): string[] {
  const boundaries = new Set<string>([
    "External caller input -> application logic",
    "Application logic -> persistent state mutations"
  ]);

  if (frameworks.includes("solana-anchor")) {
    boundaries.add("Transaction accounts -> instruction handlers");
    boundaries.add("Program -> CPI target programs");
    boundaries.add("Signer authorities -> PDA-derived authorities");
  }

  return uniqueSorted([...boundaries]);
}

function buildAttackSurface(target: ScanTarget, frameworks: string[]): string[] {
  const attackSurface = new Set<string>();

  if (frameworks.includes("solana-anchor")) {
    attackSurface.add("Account validation constraints");
    attackSurface.add("Cross-program invocation callsites");
    attackSurface.add("PDA seed derivation and bump handling");
  }

  if (target.mode === "diff") {
    attackSurface.add("Changed-file regression surface");
  } else {
    attackSurface.add("Full repository scan surface");
  }

  return uniqueSorted([...attackSurface]);
}

function buildScopeFiles(target: ScanTarget, rootPath: string, sourceFiles: string[]): string[] {
  if (target.mode === "diff" && target.diff?.changed_files) {
    const relChanged = uniqueSorted(
      target.diff.changed_files.map((filePath) => normalizeRelPath(rootPath, filePath))
    );
    return relChanged.slice(0, MAX_SCOPE_FILES);
  }

  return uniqueSorted(sourceFiles.map((filePath) => normalizeRelPath(rootPath, filePath))).slice(
    0,
    MAX_SCOPE_FILES
  );
}

function pickPrimaryLanguage(languageBreakdown: Record<string, number>): string {
  const ranked = Object.entries(languageBreakdown).sort((a, b) => b[1] - a[1]);
  return ranked[0]?.[0] ?? "unknown";
}

async function generateThreatModelSummary(
  rootPath: string,
  target: ScanTarget
): Promise<ThreatModelSummary> {
  const sourceFiles = await listSourceFiles(rootPath);
  const languageBreakdown = detectLanguageBreakdown(sourceFiles);
  const frameworks = await detectFrameworks(rootPath, sourceFiles);
  const entryPoints = await detectEntryPoints(rootPath, sourceFiles);

  return {
    primary_language: pickPrimaryLanguage(languageBreakdown),
    language_breakdown: languageBreakdown,
    detected_frameworks: frameworks,
    assets: buildAssets(frameworks),
    trust_boundaries: buildTrustBoundaries(frameworks),
    entry_points: entryPoints,
    attack_surface: buildAttackSurface(target, frameworks),
    scan_scope_files: buildScopeFiles(target, rootPath, sourceFiles)
  };
}

async function loadStore(storePath: string, rootPath: string, repoId: string): Promise<ThreatModelStore> {
  if (!(await fileExists(storePath))) {
    return {
      schema_version: THREAT_MODEL_SCHEMA_VERSION,
      repo_id: repoId,
      repo_root: rootPath,
      by_fingerprint: {},
      versions: []
    };
  }

  const raw = await fs.readFile(storePath, "utf8");
  return JSON.parse(raw) as ThreatModelStore;
}

async function writeStore(storePath: string, store: ThreatModelStore): Promise<void> {
  await fs.mkdir(path.dirname(storePath), { recursive: true });
  await fs.writeFile(storePath, JSON.stringify(store, null, 2), "utf8");
}

export async function loadOrCreateThreatModel(target: ScanTarget): Promise<ThreatModelInfo> {
  const rootPath = path.resolve(target.root_path);
  const repoId = repoIdFor(rootPath);
  const storePath = path.join(STORE_ROOT, repoId, "versions.json");
  const gitContext = await getGitContext(rootPath);
  const fingerprint = buildFingerprint(target, gitContext);
  const fingerprintHash = digest(JSON.stringify(fingerprint));

  const store = await loadStore(storePath, rootPath, repoId);
  const cachedVersionId = store.by_fingerprint[fingerprintHash];
  if (cachedVersionId) {
    const cached = store.versions.find((version) => version.id === cachedVersionId);
    if (cached) {
      return {
        version: cached,
        loaded_from_cache: true
      };
    }
  }

  const summary = await generateThreatModelSummary(rootPath, target);
  const parentVersion = store.latest_version_id
    ? store.versions.find((version) => version.id === store.latest_version_id)
    : undefined;
  const revision = (parentVersion?.revision ?? 0) + 1;
  const versionId = `${repoId}-v${String(revision).padStart(4, "0")}`;

  const version: ThreatModelVersion = {
    id: versionId,
    repo_id: repoId,
    repo_root: rootPath,
    revision,
    schema_version: THREAT_MODEL_SCHEMA_VERSION,
    created_at: new Date().toISOString(),
    parent_version_id: parentVersion?.id,
    fingerprint_hash: fingerprintHash,
    fingerprint,
    summary,
    storage_path: storePath
  };

  store.latest_version_id = version.id;
  store.by_fingerprint[fingerprintHash] = version.id;
  store.versions.push(version);
  await writeStore(storePath, store);

  return {
    version,
    loaded_from_cache: false
  };
}
