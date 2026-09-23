// Reads .egresso/audit.jsonl and prints recent decisions or a summary. The audit
// trail is the thing security/compliance teams care about most, so make it easy to see.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { loadConfig, expandHome } from "./config.js";

type Entry = {
  ts: string;
  cwd?: string;
  channel: string;
  detail: string;
  action: "allow" | "block";
  reason: string;
  destination?: string;
  hits?: { kind: string; redacted: string }[];
};

/** Resolve the same log the hook writes to — which may be central, not per-project. */
export function logPath(cwd: string): string {
  const cfg = loadConfig(cwd);
  return cfg.logFile ? expandHome(cfg.logFile) : join(cwd, ".egresso", "audit.jsonl");
}

function load(cwd: string): Entry[] {
  const file = logPath(cwd);
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l) as Entry;
      } catch {
        return null;
      }
    })
    .filter((e): e is Entry => e !== null);
}

export function showLog(cwd = process.cwd(), limit = 20): void {
  const entries = load(cwd);
  if (entries.length === 0) {
    console.log(`No audit entries yet. Decisions are logged to ${logPath(cwd)} once egresso runs.`);
    return;
  }
  for (const e of entries.slice(-limit)) {
    const icon = e.action === "block" ? "⛔" : "✓";
    const when = e.ts.replace("T", " ").slice(0, 19);
    console.log(`${icon} ${when}  ${e.channel}`);
    console.log(`   ${e.detail.slice(0, 100)}`);
    if (e.action === "block") console.log(`   → ${e.reason}`);
  }
}

export function showReport(cwd = process.cwd()): void {
  const entries = load(cwd);
  const total = entries.length;
  const blocked = entries.filter((e) => e.action === "block");
  console.log(`egresso audit summary`);
  console.log(`  actions inspected: ${total}`);
  console.log(`  blocked:           ${blocked.length}`);
  if (blocked.length) {
    const byDest = new Map<string, number>();
    for (const b of blocked) {
      const d = b.destination ?? "(no destination)";
      byDest.set(d, (byDest.get(d) ?? 0) + 1);
    }
    console.log(`  top blocked destinations:`);
    for (const [d, n] of [...byDest.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
      console.log(`    ${n}×  ${d}`);
    }
  }
}
