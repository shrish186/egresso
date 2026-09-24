// Action-level inspection. Given a tool call an agent wants to make (a shell
// command, an HTTP request, an arbitrary tool payload), decide whether it would
// exfiltrate secrets to somewhere it shouldn't — and block it before it runs.
import { scan, type SecretHit, type ScanOptions } from "../detect/secrets.js";
import { analyzeFlow, secretSourcesIn } from "./dataflow.js";

export type Decision = {
  action: "allow" | "block";
  reason: string;
  hits: SecretHit[];
  destination?: string; // host/URL the data was headed to, if known
};

export type PolicyConfig = {
  // Hosts secrets are allowed to reach (e.g. your own API). Everything else is untrusted.
  allowedDestinations?: string[]; // substrings matched against host
  scan?: ScanOptions;
};

// Pull the outbound network destination out of a shell command, if any.
// Covers the common exfil channels an injected instruction would reach for.
function extractDestination(command: string): string | undefined {
  const url = command.match(/https?:\/\/([^\s"'|>)\]]+)/i);
  if (url) {
    try {
      return new URL(url[0]).host;
    } catch {
      return url[1];
    }
  }
  // netcat / dev-tcp style exfil: `nc host port`, `/dev/tcp/host/port`
  const devtcp = command.match(/\/dev\/tcp\/([^/\s]+)\/\d+/);
  if (devtcp) return devtcp[1];
  const nc = command.match(/\bnc\s+(?:-\w+\s+)*([\w.-]+)\s+\d+/);
  if (nc) return nc[1];
  return undefined;
}

function destinationAllowed(dest: string | undefined, allow: string[]): boolean {
  if (!dest) return true; // no outbound destination in this action
  return allow.some((a) => dest.includes(a));
}

// Inspect a shell command about to be executed by an agent.
export function inspectShellCommand(command: string, policy: PolicyConfig = {}): Decision {
  const hits = scan(command, policy.scan);
  const dest = extractDestination(command);
  const allow = policy.allowedDestinations ?? [];

  // Data-flow layer: catches encoded/indirect exfiltration where no secret literal
  // appears in the text (cat .env | base64 | curl, $API_KEY refs, DNS exfil, staging).
  const flow = analyzeFlow(command);
  if (flow) {
    // On a proven source→sink path, an *unknown* destination is not a free pass:
    // secrets may only egress to a destination we can see AND that is allowlisted.
    const flowDestOk = !!dest && destinationAllowed(dest, allow);
    if (flow.sink && !flowDestOk) {
      return {
        action: "block",
        reason: `Command reads secret source(s) [${flow.sources.join(", ")}] and sends them out via ${flow.sink}${
          dest ? ` to "${dest}"` : ""
        }.`,
        hits,
        destination: dest,
      };
    }
    if (flow.staged) {
      return {
        action: "block",
        reason: `Command stages secret source(s) [${flow.sources.join(", ")}] to ${flow.staged}, outside the project.`,
        hits,
        destination: dest,
      };
    }
  }

  if (hits.length > 0 && dest && !destinationAllowed(dest, allow)) {
    return {
      action: "block",
      reason: `Command sends ${hits.length} secret(s) to untrusted host "${dest}".`,
      hits,
      destination: dest,
    };
  }
  if (hits.length > 0 && !dest) {
    // Secrets present but no network sink we recognize — surface as a warning-block
    // for review rather than silently allowing (e.g. writing keys to a world path).
    return {
      action: "block",
      reason: `Command references ${hits.length} secret(s); no allowed destination identified.`,
      hits,
    };
  }
  return { action: "allow", reason: "No secret exfiltration detected.", hits, destination: dest };
}

// Inspect an outbound HTTP request an agent wants to make.
export function inspectHttpRequest(
  req: { url: string; headers?: Record<string, string>; body?: string },
  policy: PolicyConfig = {}
): Decision {
  let host: string | undefined;
  try {
    host = new URL(req.url).host;
  } catch {
    host = undefined;
  }
  const payload = [req.url, JSON.stringify(req.headers ?? {}), req.body ?? ""].join("\n");
  const hits = scan(payload, policy.scan);
  const allow = policy.allowedDestinations ?? [];

  if (hits.length > 0 && !destinationAllowed(host, allow)) {
    return {
      action: "block",
      reason: `Request would send ${hits.length} secret(s) to untrusted host "${host}".`,
      hits,
      destination: host,
    };
  }
  return { action: "allow", reason: "No secret exfiltration detected.", hits, destination: host };
}

// Generic inspection for an arbitrary MCP tool call: scan the serialized args
// for secrets and look for a destination field.
export function inspectToolCall(
  toolName: string,
  args: unknown,
  policy: PolicyConfig = {}
): Decision {
  const serialized = typeof args === "string" ? args : JSON.stringify(args ?? {});
  const hits = scan(serialized, policy.scan);
  const dest = extractDestination(serialized);
  const allow = policy.allowedDestinations ?? [];

  // Tool calls get the same source analysis as shell commands. Without this the MCP
  // path was strictly weaker than the shell path: an agent could post
  // `$ANTHROPIC_API_KEY` or a `.env` reference through a tool and never be seen,
  // because scan() only finds secret *values*, never references to them.
  //
  // There is no sink verb to look for here — invoking the tool is itself the egress —
  // so a secret source plus a destination we do not trust is enough.
  const sources = secretSourcesIn(serialized);
  if (sources.length > 0 && !destinationAllowed(dest, allow)) {
    return {
      action: "block",
      reason: `Tool "${toolName}" references secret source(s) [${sources.join(", ")}]${
        dest ? ` with destination "${dest}"` : " and no identified destination"
      }.`,
      hits,
      destination: dest,
    };
  }

  if (hits.length > 0 && !destinationAllowed(dest, allow)) {
    return {
      action: "block",
      reason: `Tool "${toolName}" would leak ${hits.length} secret(s)${
        dest ? ` to "${dest}"` : ""
      }.`,
      hits,
      destination: dest,
    };
  }
  return { action: "allow", reason: "No secret exfiltration detected.", hits, destination: dest };
}
