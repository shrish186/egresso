// Pluggable enforcement engines for the benchmark.
//
// The point of this file is falsifiability. egresso claims that source->sink
// dataflow analysis beats pattern matching. That claim is only meaningful if a
// good-faith pattern matcher is measured on the same corpus.
//
// `regex-baseline` is therefore written to be GOOD, not a strawman: it covers
// the patterns that hook-based tools in the wild actually ship (.env reads,
// curl|sh, rm -rf, force pushes, ssh keys, cloud credentials). If egresso
// cannot beat this, egresso's dataflow layer is not buying anything and we
// should know that before building more of it.

import { evaluateCommand } from "../src/policy.js";

export type Verdict = "block" | "allow";

export type Engine = {
  name: string;
  /** How this engine decides. Printed in the report for honesty. */
  approach: string;
  run: (cmd: string) => Verdict;
};

// ---------------------------------------------------------------------------
// egresso — the real thing, via its unified policy engine.
// ---------------------------------------------------------------------------

const ALLOWED_DESTINATIONS = ["api.anthropic.com", "api.openai.com", "api.github.com", "registry.npmjs.org", "pypi.org", "example.com"];

export const egresso: Engine = {
  name: "egresso",
  approach: "source->sink dataflow taint + secret scan + destructive analysis",
  run: (cmd) => {
    const d = evaluateCommand(cmd, { allowedDestinations: ALLOWED_DESTINATIONS });
    // "ask" counts as a block for benchmark purposes: the action does not
    // execute without a human. "warn" does not stop anything, so it is allow.
    return d.verdict === "block" || d.verdict === "ask" ? "block" : "allow";
  },
};

// ---------------------------------------------------------------------------
// regex-baseline — a fair model of hook-based pattern matching.
// ---------------------------------------------------------------------------

const SECRET_PATHS = String.raw`(\.env(\.[a-z]+)?|id_rsa|id_ed25519|\.aws/credentials|\.ssh/|\.netrc|\.kube/config|\.docker/config\.json)`;
const NET_SINKS = String.raw`(curl|wget|nc|netcat|socat|scp|rsync|ssh|nslookup|dig|host)\b`;

const BASELINE_RULES: { id: string; re: RegExp }[] = [
  // Secret file read piped or posted to the network, on one line.
  { id: "secret-file-to-net", re: new RegExp(String.raw`(cat|less|head|tail|more)\s+[^|;&]*${SECRET_PATHS}[^|;&]*[|]\s*${NET_SINKS}`, "i") },
  { id: "secret-file-as-payload", re: new RegExp(String.raw`${NET_SINKS}[^\n]*(--data-binary|--post-file|-d)\s*@?[^\s]*${SECRET_PATHS}`, "i") },
  { id: "secret-file-in-subshell", re: new RegExp(String.raw`${NET_SINKS}[^\n]*\$\((cat|head|tail)[^)]*${SECRET_PATHS}`, "i") },
  // Well-known secret env vars sent outward.
  { id: "secret-envvar-to-net", re: new RegExp(String.raw`${NET_SINKS}[^\n]*\$\{?(ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|DB_PASSWORD|SECRET|API_KEY)`, "i") },
  { id: "env-dump-to-net", re: new RegExp(String.raw`\b(printenv|env|set)\b[^|;]*[|][^|;]*${NET_SINKS}`, "i") },
  // scp/rsync of secret material.
  { id: "secret-copy-remote", re: new RegExp(String.raw`(scp|rsync)[^\n]*${SECRET_PATHS}[^\n]*@`, "i") },
  { id: "secret-copy-remote-2", re: new RegExp(String.raw`(scp|rsync)[^\n]*\.ssh/?[^\n]*\s+\S+@`, "i") },
  // /dev/tcp redirect.
  { id: "devtcp", re: /\/dev\/tcp\// },
  // Destructive.
  { id: "rm-rf-root", re: /rm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\s+(\/|~\/?|\/\*)(\s|$)/ },
  { id: "force-push", re: /git\s+push\s+[^\n]*(--force(?!-with-lease)|(^|\s)-f(\s|$))/ },
  { id: "drop-db", re: /\b(DROP\s+(TABLE|DATABASE)|TRUNCATE\s+TABLE)\b/i },
  { id: "kubectl-delete-ns", re: /kubectl\s+delete\s+(namespace|ns)\b/i },
  { id: "terraform-destroy", re: /terraform\s+destroy/i },
  { id: "dd-disk", re: /dd\s+[^\n]*of=\/dev\/(sd|nvme|disk)/i },
  { id: "curl-pipe-sh", re: /(curl|wget)\s[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i },
  { id: "fork-bomb", re: /:\(\)\s*\{.*\|.*&.*\}\s*;\s*:/ },
  { id: "mkfs", re: /\bmkfs(\.\w+)?\s+\/dev\//i },
  { id: "chmod-root", re: /chmod\s+(-R\s+)?[0-7]{3,4}\s+\/(\s|$)/ },
  { id: "s3-rm-recursive", re: /aws\s+s3\s+rm\s+[^\n]*--recursive/i },
];

export const regexBaseline: Engine = {
  name: "regex-baseline",
  approach: "pattern matching on command text (models hook-based tools)",
  run: (cmd) => (BASELINE_RULES.some((r) => r.re.test(cmd)) ? "block" : "allow"),
};

// ---------------------------------------------------------------------------
// block-everything — the trivial control.
//
// Scores 100% on attacks and 0% on benign. Its only job is to make the report
// state plainly that attack-block-rate alone is a meaningless metric.
// ---------------------------------------------------------------------------

export const blockEverything: Engine = {
  name: "block-everything",
  approach: "control: blocks unconditionally",
  run: () => "block",
};

export const ENGINES: Engine[] = [egresso, regexBaseline, blockEverything];
