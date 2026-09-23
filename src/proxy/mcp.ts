// Transparent MCP proxy. Sits between an MCP client (Claude Desktop, Cursor, any
// agent) and a real MCP server, over stdio. It forwards JSON-RPC untouched except for
// `tools/call`, which it inspects first. Blocked calls never reach the real server;
// the client gets an error result explaining why. This is the vendor-neutral
// enforcement point — the same policy protects every MCP-based agent.
//
//   egresso proxy -- npx -y @some/mcp-server --flag
//
// MCP stdio framing is newline-delimited JSON (one message per line).
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { loadConfig, logDecision } from "../config.js";
import { loadKnownSecrets } from "../detect/env.js";
import { evaluateToolCall, type PolicyDecision } from "../policy.js";

type JsonRpc = {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: { name?: string; arguments?: unknown };
};

export function runProxy(argv: string[]): void {
  // Everything after "--" is the real server command.
  const sep = argv.indexOf("--");
  const serverCmd = sep === -1 ? argv : argv.slice(sep + 1);
  if (serverCmd.length === 0) {
    process.stderr.write("egresso proxy: no server command. Usage: egresso proxy -- <cmd> [args]\n");
    process.exit(1);
  }

  const cwd = process.cwd();
  const cfg = loadConfig(cwd);
  const engineCfg = { ...cfg, scan: { ...cfg.scan, knownValues: loadKnownSecrets(cwd) } };

  const child = spawn(serverCmd[0], serverCmd.slice(1), { stdio: ["pipe", "pipe", "inherit"] });
  child.on("error", (e) => {
    process.stderr.write(`egresso proxy: failed to start server: ${e.message}\n`);
    process.exit(1);
  });
  child.on("exit", (code) => process.exit(code ?? 0));

  const writeToClient = (obj: unknown) => process.stdout.write(JSON.stringify(obj) + "\n");
  const writeToServer = (line: string) => child.stdin.write(line + "\n");

  // Client -> server: inspect tools/call, forward everything else.
  const fromClient = createInterface({ input: process.stdin });
  fromClient.on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpc;
    try {
      msg = JSON.parse(line) as JsonRpc;
    } catch {
      writeToServer(line); // not JSON we understand — pass through untouched
      return;
    }

    if (msg.method === "tools/call" && msg.params?.name) {
      const toolName = msg.params.name;
      const decision = evaluateToolCall(toolName, msg.params.arguments, engineCfg);
      logDecision(cwd, cfg, { channel: `mcp:${toolName}`, detail: JSON.stringify(msg.params.arguments).slice(0, 200) }, {
        action: decision.verdict === "allow" || decision.verdict === "warn" ? "allow" : "block",
        reason: decision.reason,
        destination: decision.destination,
        hits: [],
      });

      if (decision.verdict === "block" || decision.verdict === "ask") {
        // Don't forward. Return an error result to the client so the model is told why.
        writeToClient(blockedResult(msg.id ?? null, toolName, decision));
        return;
      }
    }
    writeToServer(line);
  });
  // Client disconnected: close the server's stdin so it can shut down cleanly.
  fromClient.on("close", () => child.stdin.end());

  // Server -> client: forward untouched.
  const fromServer = createInterface({ input: child.stdout });
  fromServer.on("line", (line) => {
    if (line.trim()) process.stdout.write(line + "\n");
  });

  process.on("SIGINT", () => child.kill("SIGINT"));
  process.on("SIGTERM", () => child.kill("SIGTERM"));
}

function blockedResult(id: JsonRpc["id"], tool: string, d: PolicyDecision) {
  const detail = d.findings.length ? ` [${d.findings.join(", ")}]` : "";
  return {
    jsonrpc: "2.0",
    id,
    result: {
      isError: true,
      content: [
        {
          type: "text",
          text:
            `egresso BLOCKED tool "${tool}": ${d.reason}${detail}\n` +
            `Category: ${d.category}. This action was not executed.`,
        },
      ],
    },
  };
}
