// Claude Code PreToolUse hook. Reads the hook JSON on stdin, inspects the tool
// call, and blocks it if it would leak secrets. Wire it up in .claude/settings.json:
//
//   "hooks": {
//     "PreToolUse": [{
//       "matcher": "Bash",
//       "hooks": [{ "type": "command", "command": "npx agentwall hook" }]
//     }]
//   }
//
// Exit 0 = allow. Exit 2 = block (stderr is shown to the model as the reason).
import { loadConfig, logDecision } from "./config.js";
import { loadKnownSecrets } from "./detect/env.js";
import { inspectShellCommand, inspectToolCall, type Decision } from "./enforce/action.js";

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

export async function runHook(): Promise<void> {
  const raw = await readStdin();
  let input: HookInput = {};
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0); // can't parse — don't block the user's workflow
  }

  const cwd = input.cwd ?? process.cwd();
  const cfg = loadConfig(cwd);
  const scanOpts = { ...cfg.scan, knownValues: loadKnownSecrets(cwd) };
  const policy = { ...cfg, scan: scanOpts };

  const tool = input.tool_name ?? "";
  const ti = input.tool_input ?? {};

  let decision: Decision;
  let detail: string;
  if (tool === "Bash" && typeof ti.command === "string") {
    detail = ti.command;
    decision = inspectShellCommand(ti.command, policy);
  } else {
    detail = `${tool}(${JSON.stringify(ti).slice(0, 200)})`;
    decision = inspectToolCall(tool, ti, policy);
  }

  logDecision(cwd, cfg, { channel: `claude-code:${tool}`, detail }, decision);

  if (decision.action === "block" && cfg.mode !== "warn") {
    const found = decision.hits.map((h) => `${h.kind} (${h.redacted})`).join(", ");
    process.stderr.write(
      `agentwall BLOCKED this action: ${decision.reason}\n` +
        `Secrets detected: ${found}\n` +
        `If this is intentional, add the destination to allowedDestinations in agentwall.config.json.\n`
    );
    process.exit(2);
  }
  process.exit(0);
}
