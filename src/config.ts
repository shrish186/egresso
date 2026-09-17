// Loads agentwall config + the audit log. Config is optional; zero-config is the
// default (any outbound destination is untrusted, so any secret egress is blocked).
import { readFileSync, existsSync, appendFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import type { PolicyConfig } from "./enforce/action.js";
import type { Decision } from "./enforce/action.js";

export type AgentwallConfig = PolicyConfig & {
  logFile?: string; // default .agentwall/audit.jsonl
  mode?: "block" | "warn"; // warn = log but allow; default block
};

const CONFIG_FILES = ["agentwall.config.json", ".agentwall.json"];

export function loadConfig(cwd = process.cwd()): AgentwallConfig {
  for (const f of CONFIG_FILES) {
    const p = join(cwd, f);
    if (existsSync(p)) {
      try {
        return JSON.parse(readFileSync(p, "utf8")) as AgentwallConfig;
      } catch {
        /* fall through to defaults */
      }
    }
  }
  return {};
}

export function logDecision(
  cwd: string,
  cfg: AgentwallConfig,
  context: { channel: string; detail: string },
  decision: Decision
): void {
  const dir = join(cwd, ".agentwall");
  const file = cfg.logFile ?? join(dir, "audit.jsonl");
  const entry = {
    ts: new Date().toISOString(),
    channel: context.channel,
    detail: context.detail,
    action: decision.action,
    reason: decision.reason,
    destination: decision.destination,
    hits: decision.hits.map((h) => ({ kind: h.kind, redacted: h.redacted })),
  };
  try {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    appendFileSync(file, JSON.stringify(entry) + "\n");
  } catch {
    /* logging must never crash enforcement */
  }
}
