// Loads egresso config + the audit log. Config is optional; zero-config is the
// default (any outbound destination is untrusted, so any secret egress is blocked).
import { readFileSync, existsSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { PolicyConfig } from "./enforce/action.js";
import type { Decision } from "./enforce/action.js";

export type EgressoConfig = PolicyConfig & {
  logFile?: string; // default .egresso/audit.jsonl; ~ is expanded
  mode?: "block" | "warn"; // warn = log but allow; default block
};

const CONFIG_FILES = ["egresso.config.json", ".egresso.json"];

/** `~/foo` -> `/Users/you/foo`. Lets one config point every project at one log. */
export function expandHome(p: string): string {
  return p.startsWith("~/") || p === "~" ? join(homedir(), p.slice(1)) : p;
}

function readConfig(p: string): EgressoConfig | null {
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as EgressoConfig;
  } catch {
    return null; // malformed config must not disable enforcement
  }
}

// Project config wins; otherwise fall back to a user-level default, so a single
// file can put every project into warn mode and log to one place — which is what
// a multi-day evaluation run needs.
export function loadConfig(cwd = process.cwd()): EgressoConfig {
  for (const f of CONFIG_FILES) {
    const found = readConfig(join(cwd, f));
    if (found) return found;
  }
  for (const p of [join(homedir(), ".egresso.json"), join(homedir(), ".config", "egresso", "config.json")]) {
    const found = readConfig(p);
    if (found) return found;
  }
  return {};
}

export function logDecision(
  cwd: string,
  cfg: EgressoConfig,
  context: { channel: string; detail: string; enforced?: boolean },
  decision: Decision
): void {
  const file = cfg.logFile ? expandHome(cfg.logFile) : join(cwd, ".egresso", "audit.jsonl");
  const entry = {
    ts: new Date().toISOString(),
    cwd, // which project this came from — a shared log spans many
    channel: context.channel,
    detail: context.detail,
    action: decision.action,
    // false when warn mode let a would-be block through
    enforced: context.enforced ?? true,
    reason: decision.reason,
    destination: decision.destination,
    hits: decision.hits.map((h) => ({ kind: h.kind, redacted: h.redacted })),
  };
  try {
    // Create the parent of the file we actually write, which is not necessarily
    // inside cwd once logFile points somewhere central.
    const parent = file.slice(0, file.lastIndexOf("/"));
    if (parent && !existsSync(parent)) mkdirSync(parent, { recursive: true });
    appendFileSync(file, JSON.stringify(entry) + "\n");
  } catch {
    /* logging must never crash enforcement */
  }
}
