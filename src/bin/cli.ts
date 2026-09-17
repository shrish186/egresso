#!/usr/bin/env node
// agentwall CLI. Subcommands:
//   hook          Run as a Claude Code PreToolUse hook (reads stdin JSON).
//   scan <file>   Scan a file (or stdin) for secrets and print hits.
//   check <cmd>   Inspect a shell command string and print the allow/block decision.
//   init          Write a starter agentwall.config.json.
import { runHook } from "../hook.js";
import { scan } from "../detect/secrets.js";
import { loadKnownSecrets } from "../detect/env.js";
import { inspectShellCommand } from "../enforce/action.js";
import { loadConfig } from "../config.js";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const cwd = process.cwd();

  switch (cmd) {
    case "hook":
      await runHook();
      return;

    case "scan": {
      const text = args[0] ? readFileSync(args[0], "utf8") : await readStdin();
      const hits = scan(text, { knownValues: loadKnownSecrets(cwd) });
      if (hits.length === 0) {
        console.log("✓ No secrets detected.");
      } else {
        console.log(`⚠ ${hits.length} secret(s) detected:`);
        for (const h of hits) console.log(`  - ${h.kind}: ${h.redacted}`);
        process.exitCode = 1;
      }
      return;
    }

    case "check": {
      const command = args.join(" ");
      const cfg = loadConfig(cwd);
      const decision = inspectShellCommand(command, {
        ...cfg,
        scan: { ...cfg.scan, knownValues: loadKnownSecrets(cwd) },
      });
      const icon = decision.action === "block" ? "⛔ BLOCK" : "✓ ALLOW";
      console.log(`${icon}: ${decision.reason}`);
      if (decision.destination) console.log(`  destination: ${decision.destination}`);
      for (const h of decision.hits) console.log(`  secret: ${h.kind} (${h.redacted})`);
      process.exitCode = decision.action === "block" ? 1 : 0;
      return;
    }

    case "init": {
      const path = "agentwall.config.json";
      if (existsSync(path)) {
        console.log(`${path} already exists.`);
        return;
      }
      const starter = {
        mode: "block",
        allowedDestinations: ["api.openai.com", "api.anthropic.com"],
      };
      writeFileSync(path, JSON.stringify(starter, null, 2) + "\n");
      console.log(`Wrote ${path}. Add the hook to .claude/settings.json to enforce.`);
      return;
    }

    default:
      console.log(
        `agentwall — a firewall for AI agents (secret-exfiltration wedge)\n\n` +
          `Usage:\n` +
          `  agentwall hook          Run as a Claude Code PreToolUse hook\n` +
          `  agentwall scan <file>   Scan a file or stdin for secrets\n` +
          `  agentwall check "<cmd>" Decide whether a shell command would leak secrets\n` +
          `  agentwall init          Write a starter config\n`
      );
      process.exitCode = cmd ? 1 : 0;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
