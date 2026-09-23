#!/usr/bin/env node
// egresso CLI.
//   hook            Run as a Claude Code PreToolUse hook (reads stdin JSON).
//   proxy -- <cmd>  Wrap an MCP server; inspect every tools/call.
//   check "<cmd>"   Evaluate a shell command and print the verdict.
//   scan <file>     Scan a file (or stdin) for secrets.
//   init            Wire the hook into .claude/settings.json + starter config.
//   doctor          Verify the setup.
//   log [n]         Show recent audit decisions.
//   report          Print an audit summary.
import { runHook } from "../hook.js";
import { runProxy } from "../proxy/mcp.js";
import { scan } from "../detect/secrets.js";
import { loadKnownSecrets } from "../detect/env.js";
import { loadConfig } from "../config.js";
import { evaluateCommand } from "../policy.js";
import { runInit, runDoctor } from "../setup.js";
import { showLog, showReport } from "../report.js";
import { readFileSync } from "node:fs";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

const ICON: Record<string, string> = { allow: "✓ ALLOW", warn: "⚠ WARN", ask: "🙋 ASK", block: "⛔ BLOCK" };

async function main() {
  const [cmd, ...args] = process.argv.slice(2);
  const cwd = process.cwd();

  switch (cmd) {
    case "hook":
      await runHook();
      return;

    case "proxy":
      runProxy(args);
      return;

    case "scan": {
      const text = args[0] ? readFileSync(args[0], "utf8") : await readStdin();
      const hits = scan(text, { knownValues: loadKnownSecrets(cwd) });
      if (hits.length === 0) console.log("✓ No secrets detected.");
      else {
        console.log(`⚠ ${hits.length} secret(s) detected:`);
        for (const h of hits) console.log(`  - ${h.kind}: ${h.redacted}`);
        process.exitCode = 1;
      }
      return;
    }

    case "check": {
      const command = args.join(" ");
      const cfg = loadConfig(cwd);
      const d = evaluateCommand(command, { ...cfg, scan: { ...cfg.scan, knownValues: loadKnownSecrets(cwd) } });
      console.log(`${ICON[d.verdict]} (${d.category}): ${d.reason}`);
      if (d.destination) console.log(`  destination: ${d.destination}`);
      for (const f of d.findings) console.log(`  finding: ${f}`);
      process.exitCode = d.verdict === "block" || d.verdict === "ask" ? 1 : 0;
      return;
    }

    case "init":
      runInit(cwd);
      return;

    case "doctor":
      runDoctor(cwd);
      return;

    case "log":
      showLog(cwd, args[0] ? parseInt(args[0], 10) : 20);
      return;

    case "report":
      showReport(cwd);
      return;

    default:
      console.log(
        `egresso — a firewall for AI agents\n\n` +
          `  egresso init            Wire the Claude Code hook + starter config\n` +
          `  egresso doctor          Verify enforcement is live\n` +
          `  egresso proxy -- <cmd>  Wrap an MCP server and inspect every tool call\n` +
          `  egresso check "<cmd>"   Evaluate a shell command\n` +
          `  egresso scan <file>     Scan a file/stdin for secrets\n` +
          `  egresso log [n]         Show recent audit decisions\n` +
          `  egresso report          Audit summary\n` +
          `  egresso hook            (used by the Claude Code hook)\n`
      );
      process.exitCode = cmd ? 1 : 0;
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
