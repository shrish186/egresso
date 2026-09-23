// Claude Code PreToolUse hook. Reads the hook JSON on stdin, evaluates the tool call
// against the full policy engine (secret exfiltration + destructive actions + custom
// rules), and blocks or asks-for-approval before the tool runs. Wire it up with
// `egresso init`, or manually in .claude/settings.json:
//
//   "hooks": { "PreToolUse": [{ "matcher": "Bash",
//     "hooks": [{ "type": "command", "command": "npx egresso hook" }] }] }
//
// Signalling: we emit Claude Code's hookSpecificOutput JSON so we can return
// allow / ask / deny. Exit 0 always; the JSON carries the decision.
import { loadConfig, logDecision } from "./config.js";
import { loadKnownSecrets } from "./detect/env.js";
import { evaluateCommand, evaluateToolCall, type PolicyDecision } from "./policy.js";

type HookInput = {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  cwd?: string;
};

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function emit(decision: PolicyDecision): void {
  const permissionDecision =
    decision.verdict === "block" ? "deny" : decision.verdict === "ask" ? "ask" : "allow";
  if (permissionDecision === "allow") {
    process.exit(0); // stay silent; let normal permissioning proceed
  }
  const detail = decision.findings.length ? ` [${decision.findings.join(", ")}]` : "";
  const reason = `egresso (${decision.category}): ${decision.reason}${detail}`;
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision,
        permissionDecisionReason: reason,
      },
    }) + "\n"
  );
  process.exit(0);
}

export async function runHook(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput = {};
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const cwd = input.cwd ?? process.cwd();
  const cfg = loadConfig(cwd);
  const engineCfg = { ...cfg, scan: { ...cfg.scan, knownValues: loadKnownSecrets(cwd) } };

  const tool = input.tool_name ?? "";
  const ti = input.tool_input ?? {};

  let decision: PolicyDecision;
  let detail: string;
  if (tool === "Bash" && typeof ti.command === "string") {
    detail = ti.command;
    decision = evaluateCommand(ti.command, engineCfg);
  } else {
    detail = `${tool}(${JSON.stringify(ti).slice(0, 200)})`;
    decision = evaluateToolCall(tool, ti, engineCfg);
  }

  logDecision(
    cwd,
    cfg,
    { channel: `claude-code:${tool}`, detail },
    {
      action: decision.verdict === "block" ? "block" : "allow",
      reason: decision.reason,
      destination: decision.destination,
      hits: [],
    }
  );

  emit(decision);
}
