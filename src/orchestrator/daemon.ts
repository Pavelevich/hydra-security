import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { runDiffScan, runFullScan } from "./run-scan";
import type { ScanResult } from "../types";

type RunStatus = "queued" | "running" | "completed" | "failed";

interface TriggerRequest {
  target_path: string;
  mode?: "full" | "diff";
  trigger?: string;
  base_ref?: string;
  head_ref?: string;
  changed_files?: string[];
}

interface RunRecord {
  id: string;
  target_path: string;
  mode: "full" | "diff";
  trigger: string;
  base_ref?: string;
  head_ref?: string;
  changed_files?: string[];
  status: RunStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error?: string;
  result?: ScanResult;
}

interface DaemonOptions {
  host: string;
  port: number;
}

const MAX_STORED_RUNS = 200;
const MAX_BODY_BYTES = 1024 * 1024;
const runs = new Map<string, RunRecord>();

function trimRunHistory(): void {
  if (runs.size <= MAX_STORED_RUNS) {
    return;
  }

  const ordered = [...runs.values()].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
  );
  const removeCount = runs.size - MAX_STORED_RUNS;
  for (const run of ordered.slice(0, removeCount)) {
    runs.delete(run.id);
  }
}

function writeJson(res: ServerResponse, body: unknown, status = 200): void {
  res.statusCode = status;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body, null, 2));
}

function writeNotFound(res: ServerResponse): void {
  writeJson(res, { error: "not_found" }, 404);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;

  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error("request_too_large");
    }
    chunks.push(buf);
  }

  if (total === 0) {
    return {};
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function validateTargetPath(targetPathInput: string): Promise<string> {
  const resolved = path.resolve(targetPathInput);
  const stat = await fs.stat(resolved);
  if (!stat.isDirectory()) {
    throw new Error(`Target path is not a directory: ${resolved}`);
  }
  return resolved;
}

async function executeRun(runId: string): Promise<void> {
  const record = runs.get(runId);
  if (!record) {
    return;
  }

  record.status = "running";
  record.started_at = new Date().toISOString();

  try {
    const result =
      record.mode === "diff"
        ? await runDiffScan(record.target_path, {
            baseRef: record.base_ref,
            headRef: record.head_ref,
            changedFiles: record.changed_files
          })
        : await runFullScan(record.target_path);
    record.status = "completed";
    record.result = result;
    record.completed_at = new Date().toISOString();
  } catch (error) {
    record.status = "failed";
    record.error = error instanceof Error ? error.message : "Unknown run error";
    record.completed_at = new Date().toISOString();
  }
}

async function handleTrigger(req: IncomingMessage, res: ServerResponse): Promise<void> {
  let payload: TriggerRequest;
  try {
    payload = (await readJsonBody(req)) as TriggerRequest;
  } catch (error) {
    const message = error instanceof Error ? error.message : "invalid_json";
    if (message === "request_too_large") {
      writeJson(res, { error: "request_too_large" }, 413);
      return;
    }
    writeJson(res, { error: "invalid_json" }, 400);
    return;
  }

  if (!payload?.target_path) {
    writeJson(res, { error: "missing_target_path" }, 400);
    return;
  }

  const mode = payload.mode ?? "full";
  if (mode !== "full" && mode !== "diff") {
    writeJson(res, { error: "invalid_mode", allowed: ["full", "diff"] }, 400);
    return;
  }
  if (payload.head_ref && !payload.base_ref) {
    writeJson(res, { error: "head_ref_requires_base_ref" }, 400);
    return;
  }
  if (payload.changed_files && !Array.isArray(payload.changed_files)) {
    writeJson(res, { error: "changed_files_must_be_array" }, 400);
    return;
  }
  const changedFiles =
    payload.changed_files?.filter((filePath): filePath is string => typeof filePath === "string") ??
    undefined;

  let targetPath: string;
  try {
    targetPath = await validateTargetPath(payload.target_path);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid target path";
    writeJson(res, { error: "invalid_target_path", detail: message }, 400);
    return;
  }

  const id = crypto.randomUUID();
  const record: RunRecord = {
    id,
    target_path: targetPath,
    mode,
    trigger: payload.trigger ?? "manual",
    base_ref: payload.base_ref?.trim() || undefined,
    head_ref: payload.head_ref?.trim() || undefined,
    changed_files: changedFiles,
    status: "queued",
    created_at: new Date().toISOString()
  };

  runs.set(id, record);
  trimRunHistory();

  queueMicrotask(() => {
    void executeRun(id);
  });

  writeJson(
    res,
    {
      run_id: id,
      status: record.status,
      target_path: record.target_path,
      mode: record.mode,
      base_ref: record.base_ref,
      head_ref: record.head_ref,
      changed_files: record.changed_files
    },
    202
  );
}

function handleGetRun(pathname: string, res: ServerResponse): void {
  const runId = pathname.split("/")[2];
  if (!runId) {
    writeNotFound(res);
    return;
  }
  const record = runs.get(runId);
  if (!record) {
    writeNotFound(res);
    return;
  }
  writeJson(res, record);
}

function handleListRuns(res: ServerResponse): void {
  const ordered = [...runs.values()].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
  writeJson(res, { runs: ordered });
}

export function startOrchestratorDaemon(options: DaemonOptions): void {
  const server = createServer(async (req, res) => {
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", `http://${options.host}:${options.port}`);
    const { pathname } = url;

    if (method === "GET" && pathname === "/healthz") {
      writeJson(res, { status: "ok" });
      return;
    }

    if (method === "GET" && pathname === "/runs") {
      handleListRuns(res);
      return;
    }

    if (method === "GET" && pathname.startsWith("/runs/")) {
      handleGetRun(pathname, res);
      return;
    }

    if (method === "POST" && pathname === "/trigger") {
      await handleTrigger(req, res);
      return;
    }

    writeNotFound(res);
  });

  server.listen(options.port, options.host, () => {
    console.log(
      `Hydra orchestrator daemon listening on http://${options.host}:${options.port} (runs retained: ${MAX_STORED_RUNS})`
    );
  });
}
