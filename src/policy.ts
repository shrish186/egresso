// Unified policy engine. One entry point evaluates a command (or tool call) against
// every enforcement module — secret exfiltration, destructive actions, and the user's
// own custom rules — and returns a single verdict: allow / warn / ask / block.
import { inspectShellCommand, inspectToolCall, type PolicyConfig } from "./enforce/action.js";
import { analyzeDestructive } from "./enforce/destructive.js";
import type { ScanOptions } from "./detect/secrets.js";

export type Verdict = "allow" | "warn" | "ask" | "block";
export type Category = "secret-exfiltration" | "destructive" | "custom" | "clean";

export type PolicyDecision = {
  verdict: Verdict; // what is ENFORCED (already downgraded by warn mode)
  /** What the policy would have done ignoring `mode`. Warn-mode evaluation runs
   *  depend on this: without it the audit log records every near-miss as "allow"
   *  and the whole point of a warn week is lost. */
  rawVerdict?: Verdict;
  category: Category;
  severity: "high" | "medium" | "low";
  reason: string;
  findings: string[]; // human-readable, secrets already redacted
  destination?: string;
};

export type CustomRule = {
  id: string;
  pattern: string; // regex source
  flags?: string;
  action: Verdict;
  message?: string;
};

export type EngineConfig = PolicyConfig & {
  mode?: "block" | "warn"; // global downgrade: "warn" turns every block into warn
  scan?: ScanOptions;
  // What to do with destructive findings, per severity. Defaults below.
  destructive?: {
    high?: Verdict; // default "block"
    medium?: Verdict; // default "ask"
    off?: boolean; // disable the module entirely
  };
  customRules?: CustomRule[];
};

const RANK: Record<Verdict, number> = { allow: 0, warn: 1, ask: 2, block: 3 };

// Global "warn" mode softens anything stricter than warn down to warn.
function applyMode(v: Verdict, mode: EngineConfig["mode"]): Verdict {
  if (mode === "warn" && RANK[v] > RANK.warn) return "warn";
  return v;
}

export function evaluateCommand(command: string, cfg: EngineConfig = {}): PolicyDecision {
  const candidates: PolicyDecision[] = [];

  // 1. Custom rules first — they express the user's explicit intent.
  for (const rule of cfg.customRules ?? []) {
    try {
      if (new RegExp(rule.pattern, rule.flags).test(command)) {
        candidates.push({
          verdict: rule.action,
          category: "custom",
          severity: rule.action === "block" ? "high" : "medium",
          reason: rule.message ?? `Matched custom rule "${rule.id}".`,
          findings: [rule.id],
        });
      }
    } catch {
      /* invalid regex in config — ignore that rule */
    }
  }

  // 2. Secret exfiltration.
  const exfil = inspectShellCommand(command, cfg);
  if (exfil.action === "block") {
    candidates.push({
      verdict: "block",
      category: "secret-exfiltration",
      severity: "high",
      reason: exfil.reason,
      findings: exfil.hits.map((h) => `${h.kind} (${h.redacted})`),
      destination: exfil.destination,
    });
  }

  // 3. Destructive actions.
  if (!cfg.destructive?.off) {
    const hi = cfg.destructive?.high ?? "block";
    const med = cfg.destructive?.medium ?? "ask";
    for (const d of analyzeDestructive(command)) {
      candidates.push({
        verdict: d.severity === "high" ? hi : med,
        category: "destructive",
        severity: d.severity,
        reason: d.description,
        findings: [d.rule],
      });
    }
  }

  if (candidates.length === 0) {
    return { verdict: "allow", rawVerdict: "allow", category: "clean", severity: "low", reason: "No policy violation.", findings: [] };
  }

  // Strictest verdict wins; merge findings from every candidate at that level+above.
  const worst = candidates.reduce((a, b) => (RANK[b.verdict] > RANK[a.verdict] ? b : a));
  const merged = candidates.filter((c) => RANK[c.verdict] >= RANK.warn);
  return {
    ...worst,
    verdict: applyMode(worst.verdict, cfg.mode),
    rawVerdict: worst.verdict,
    findings: [...new Set(merged.flatMap((c) => c.findings))],
    reason: worst.reason,
  };
}

// For non-shell MCP tool calls: run the secret + custom layers on the serialized args.
export function evaluateToolCall(
  toolName: string,
  args: unknown,
  cfg: EngineConfig = {}
): PolicyDecision {
  const serialized = typeof args === "string" ? args : JSON.stringify(args ?? {});
  const candidates: PolicyDecision[] = [];

  for (const rule of cfg.customRules ?? []) {
    try {
      if (new RegExp(rule.pattern, rule.flags).test(serialized)) {
        candidates.push({
          verdict: rule.action,
          category: "custom",
          severity: rule.action === "block" ? "high" : "medium",
          reason: rule.message ?? `Matched custom rule "${rule.id}".`,
          findings: [rule.id],
        });
      }
    } catch {
      /* ignore */
    }
  }

  const exfil = inspectToolCall(toolName, args, cfg);
  if (exfil.action === "block") {
    candidates.push({
      verdict: "block",
      category: "secret-exfiltration",
      severity: "high",
      reason: exfil.reason,
      findings: exfil.hits.map((h) => `${h.kind} (${h.redacted})`),
      destination: exfil.destination,
    });
  }

  if (candidates.length === 0) {
    return { verdict: "allow", rawVerdict: "allow", category: "clean", severity: "low", reason: "No policy violation.", findings: [] };
  }
  const worst = candidates.reduce((a, b) => (RANK[b.verdict] > RANK[a.verdict] ? b : a));
  return { ...worst, verdict: applyMode(worst.verdict, cfg.mode), rawVerdict: worst.verdict };
}
