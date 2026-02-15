/**
 * Agent Result Cache
 *
 * Content-hash-based caching for scanner results. Avoids re-scanning files
 * whose content hasn't changed since the last scan. Stores results keyed by
 * (scanner_id, file_content_hash) pairs.
 */

import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding } from "../types";

export interface CacheEntry {
  scanner_id: string;
  file_path: string;
  content_hash: string;
  findings: Finding[];
  cached_at: string;
  ttl_ms: number;
}

export interface CacheStats {
  total_entries: number;
  hits: number;
  misses: number;
  evictions: number;
  hit_rate: number;
}

interface CacheStore {
  schema_version: string;
  entries: Record<string, CacheEntry>;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_CACHE_ENTRIES = 5_000;
const CACHE_SCHEMA_VERSION = "1.0.0";

function contentHash(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

function cacheKey(scannerId: string, filePath: string, fileContentHash: string): string {
  // Include file path in key to prevent same-content files from cross-contaminating
  // cached findings (findings include file_path, so different files must have separate entries).
  const pathHash = createHash("sha256").update(filePath).digest("hex").slice(0, 12);
  return `${scannerId}:${pathHash}:${fileContentHash}`;
}

function isExpired(entry: CacheEntry): boolean {
  const age = Date.now() - new Date(entry.cached_at).getTime();
  return age > entry.ttl_ms;
}

export class ScanCache {
  private store: CacheStore;
  private storePath: string;
  private dirty = false;
  private stats: CacheStats = { total_entries: 0, hits: 0, misses: 0, evictions: 0, hit_rate: 0 };

  private constructor(store: CacheStore, storePath: string) {
    this.store = store;
    this.storePath = storePath;
    this.stats.total_entries = Object.keys(store.entries).length;
  }

  static async load(cacheDir?: string): Promise<ScanCache> {
    const dir = cacheDir ?? path.resolve(".hydra/scan-cache");
    const storePath = path.join(dir, "cache.json");

    try {
      const raw = await fs.readFile(storePath, "utf8");
      const store = JSON.parse(raw) as CacheStore;
      if (store.schema_version !== CACHE_SCHEMA_VERSION) {
        return new ScanCache({ schema_version: CACHE_SCHEMA_VERSION, entries: {} }, storePath);
      }
      return new ScanCache(store, storePath);
    } catch {
      return new ScanCache({ schema_version: CACHE_SCHEMA_VERSION, entries: {} }, storePath);
    }
  }

  lookup(scannerId: string, filePath: string, fileContent: string): Finding[] | undefined {
    const hash = contentHash(fileContent);
    const key = cacheKey(scannerId, filePath, hash);
    const entry = this.store.entries[key];

    if (!entry) {
      this.stats.misses++;
      this.updateHitRate();
      return undefined;
    }

    if (isExpired(entry)) {
      delete this.store.entries[key];
      this.dirty = true;
      this.stats.misses++;
      this.stats.evictions++;
      this.updateHitRate();
      return undefined;
    }

    this.stats.hits++;
    this.updateHitRate();
    return entry.findings;
  }

  put(scannerId: string, filePath: string, fileContent: string, findings: Finding[], ttlMs?: number): void {
    const hash = contentHash(fileContent);
    const key = cacheKey(scannerId, filePath, hash);

    this.store.entries[key] = {
      scanner_id: scannerId,
      file_path: filePath,
      content_hash: hash,
      findings,
      cached_at: new Date().toISOString(),
      ttl_ms: ttlMs ?? DEFAULT_TTL_MS
    };

    this.dirty = true;
    this.evictIfNeeded();
  }

  getStats(): CacheStats {
    return { ...this.stats, total_entries: Object.keys(this.store.entries).length };
  }

  invalidateScanner(scannerId: string): number {
    let count = 0;
    for (const [key, entry] of Object.entries(this.store.entries)) {
      if (entry.scanner_id === scannerId) {
        delete this.store.entries[key];
        count++;
      }
    }
    if (count > 0) this.dirty = true;
    return count;
  }

  invalidateAll(): void {
    this.store.entries = {};
    this.dirty = true;
  }

  async flush(): Promise<void> {
    if (!this.dirty) return;

    await fs.mkdir(path.dirname(this.storePath), { recursive: true });
    await fs.writeFile(this.storePath, JSON.stringify(this.store, null, 2), "utf8");
    this.dirty = false;
  }

  private evictIfNeeded(): void {
    const keys = Object.keys(this.store.entries);
    if (keys.length <= MAX_CACHE_ENTRIES) return;

    // Evict oldest entries first
    const sorted = keys
      .map((key) => ({ key, cached_at: new Date(this.store.entries[key].cached_at).getTime() }))
      .sort((a, b) => a.cached_at - b.cached_at);

    const removeCount = keys.length - MAX_CACHE_ENTRIES;
    for (let i = 0; i < removeCount; i++) {
      delete this.store.entries[sorted[i].key];
      this.stats.evictions++;
    }
  }

  private updateHitRate(): void {
    const total = this.stats.hits + this.stats.misses;
    this.stats.hit_rate = total > 0 ? this.stats.hits / total : 0;
  }
}

/**
 * Helper: hash a file's content for cache key generation.
 */
export async function hashFileContent(filePath: string): Promise<string> {
  const content = await fs.readFile(filePath, "utf8");
  return contentHash(content);
}

/**
 * Helper: check if a file's scan results are cached.
 */
export async function isCached(
  cache: ScanCache,
  scannerId: string,
  filePath: string
): Promise<boolean> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    return cache.lookup(scannerId, filePath, content) !== undefined;
  } catch {
    return false;
  }
}
