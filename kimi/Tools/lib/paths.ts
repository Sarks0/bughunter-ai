/**
 * Shared path resolution for BugHunter AI Kimi port.
 * All runtime data lives under <repo-root>/kimi-data/.
 */
import { join, dirname } from "path";

/** Repository root (one level above kimi/Tools/). */
export const REPO_ROOT = dirname(dirname(dirname(import.meta.dir)));

/** Runtime data directory. */
export const DATA_DIR = join(REPO_ROOT, "kimi-data");

/** Session storage. */
export const SESSIONS_DIR = join(DATA_DIR, "Sessions");

/** Persistent memory directories. */
export const MEMORY_DIR = {
  findings: join(DATA_DIR, "Findings"),
  learning: join(DATA_DIR, "LearningLogs"),
  patterns: join(DATA_DIR, "PatternDB"),
  profiles: join(DATA_DIR, "TargetProfiles"),
  vault: join(DATA_DIR, "Vault"),
};

/** Wordlists shipped with the Kimi port. */
export const WORDLISTS_DIR = join(REPO_ROOT, "kimi", "Wordlists");

/** Templates shipped with the Kimi port. */
export const TEMPLATES_DIR = join(REPO_ROOT, "kimi", "Templates");

export function getSessionDir(targetSlug: string): string {
  return join(SESSIONS_DIR, targetSlug);
}

export function ensureDataDirs(): void {
  for (const dir of [DATA_DIR, SESSIONS_DIR, ...Object.values(MEMORY_DIR)]) {
    Bun.write(join(dir, ".gitkeep"), "");
  }
}
