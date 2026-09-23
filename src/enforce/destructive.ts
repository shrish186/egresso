// Second failure mode: destructive actions. Agents given shell access can wipe
// files, force-push over history, drop databases, or delete cloud/k8s resources —
// often triggered by a confused plan or a prompt injection, not malice. We flag the
// high-blast-radius ones so they can be blocked or sent for human approval.
//
// The hard requirement here is NOT catching everything — it is not crying wolf.
// `rm -rf node_modules` is the single most common command in JavaScript development,
// and a tool that blocks it gets uninstalled within the hour. So these rules look at
// the TARGET of a destructive verb, not just the verb.

export type DestructiveFinding = {
  rule: string; // stable id, e.g. "rm-rf-root"
  severity: "high" | "medium";
  description: string;
};

// ---------------------------------------------------------------------------
// rm — target-aware, because the verb alone says nothing about blast radius.
// ---------------------------------------------------------------------------

/** Paths whose deletion is catastrophic and never routine. */
const CATASTROPHIC_TARGET =
  /^(\/|\/\*|~|~\/|~\/\*|\$HOME|\$HOME\/\*?|\/(?:etc|usr|bin|sbin|lib|boot|dev|sys|proc|opt|srv|root)(?:\/\*?)?|\*|\.|\.\/\*)$/;

/** Build artifacts and scratch paths: deleting these is ordinary development. */
const SAFE_TARGET =
  /(^|\/)(node_modules|dist|build|out|target|coverage|\.cache|\.next|\.nuxt|\.turbo|\.parcel-cache|__pycache__|\.pytest_cache|\.venv|venv|vendor|bin\/debug|obj)(\/.*)?$|^\/(?:tmp|var\/tmp|private\/tmp)\/\S+|\.(log|tmp|lock|pyc|o|class)$/i;

/** Pull the operand paths out of an `rm ...` invocation. */
function rmTargets(command: string): string[] {
  const m = command.match(/\brm\b((?:\s+(?:-{1,2}[\w-]+|[^\s;|&]+))*)/);
  if (!m) return [];
  return (m[1].match(/[^\s;|&]+/g) ?? []).filter((t) => !t.startsWith("-"));
}

function analyzeRm(command: string): DestructiveFinding | null {
  if (!/\brm\b/.test(command)) return null;
  const recursive = /\brm\s+(?:-{1,2}[\w-]+\s+)*-[a-zA-Z]*r/i.test(command) || /--recursive/.test(command);
  const targets = rmTargets(command);
  if (targets.length === 0) return null;

  if (targets.some((t) => CATASTROPHIC_TARGET.test(t))) {
    return {
      rule: "rm-rf-root",
      severity: "high",
      description: "Recursive force-delete of a root/home/wildcard path.",
    };
  }

  // Recursive delete of something that is not a recognized build artifact:
  // worth a human glance, but not a hard block.
  if (recursive && !targets.every((t) => SAFE_TARGET.test(t))) {
    return {
      rule: "rm-rf-unscoped",
      severity: "medium",
      description: `Recursive delete of ${targets.join(", ")}. Review the target path.`,
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Everything else: plain pattern rules, but scoped so routine work passes.
// ---------------------------------------------------------------------------

type Rule = { id: string; severity: "high" | "medium"; re: RegExp; description: string };

const RULES: Rule[] = [
  {
    id: "git-force-push",
    severity: "high",
    // --force-with-lease is the safe variant and must not trip this.
    re: /\bgit\s+push\b[^\n]*(?:--force(?!-with-lease)\b|\s-f\b)(?![-\w])/,
    description: "Force-push can overwrite remote history for everyone.",
  },
  {
    id: "git-deep-reset",
    severity: "medium",
    // `git reset --hard HEAD` is routine. Discarding many commits is not.
    re: /\bgit\s+reset\s+--hard\s+(?:HEAD[~^]\d*[~^\d]*|[0-9a-f]{7,40})\b/,
    description: "Hard reset to an earlier commit discards work.",
  },
  {
    id: "git-clean-ignored",
    severity: "medium",
    // -x also removes gitignored files, which is where .env lives.
    re: /\bgit\s+clean\b[^\n]*-[a-zA-Z]*x/,
    description: "git clean -x removes ignored files, including .env.",
  },
  {
    id: "db-drop",
    severity: "high",
    re: /\b(DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE?|DELETE\s+FROM\s+\w+\s*(?:;|$))/i,
    description: "Destructive SQL: drop/truncate/unfiltered delete.",
  },
  {
    id: "k8s-delete-scope",
    severity: "high",
    // Deleting a namespace/deployment/PVC or using --all is high blast radius.
    // Deleting one crashlooping pod is routine operations work.
    re: /\bkubectl\s+delete\s+(?:namespace|ns|deployment|deploy|statefulset|sts|pvc|persistentvolumeclaim|node)\b|\bkubectl\s+delete\b[^\n]*--all\b|\bhelm\s+(?:delete|uninstall)\b/,
    description: "Deleting a namespace, workload, or volume.",
  },
  {
    id: "cloud-destroy",
    severity: "high",
    re: /\bterraform\s+destroy\b|\baws\s+\w+\s+(?:delete|terminate|remove)-|\baws\s+s3\s+(?:rm\b[^\n]*--recursive|rb\b)|\bgcloud\s+\w+\s+delete\b|\baz\s+group\s+delete\b/,
    description: "Tearing down cloud infrastructure or bulk-deleting object storage.",
  },
  {
    id: "disk-write",
    severity: "high",
    re: /\b(?:dd\s+[^\n]*of=\/dev\/|mkfs(?:\.[a-z0-9]+)?\s+\/dev\/|>\s*\/dev\/sd[a-z])/,
    description: "Writing directly to a block device wipes it.",
  },
  {
    id: "chmod-root-permissive",
    severity: "high",
    // Recursive world-writable on a system root, not on a project file.
    re: /\bchmod\s+-R\s+0?777\s+(?:\/|~|\$HOME)(?:\s|$)/,
    description: "Recursively world-writable permissions on a system path.",
  },
  {
    id: "fork-bomb",
    severity: "high",
    re: /:\(\)\s*\{\s*:\|:&\s*\}\s*;/,
    description: "Shell fork bomb.",
  },
  {
    id: "datastore-flush",
    severity: "high",
    re: /\bredis-cli\b[^\n]*\b(?:FLUSHALL|FLUSHDB)\b|\bdropDatabase\s*\(|\bdb\.\w+\.drop\s*\(|\betcdctl\s+del\b[^\n]*--prefix/i,
    description: "Flushing or dropping an entire datastore.",
  },
  {
    id: "container-mass-delete",
    severity: "high",
    // Targeting a subshell that enumerates everything, or pruning volumes (data).
    re: /\bdocker\s+(?:rm|stop|kill)\b[^\n]*\$\((?:docker|podman)\s+ps[^)]*\)|\bdocker\s+volume\s+prune\b|\bdocker\s+system\s+prune\b[^\n]*(?:--volumes|-a\b[^\n]*--volumes)/,
    description: "Removing all containers or pruning data volumes.",
  },
  {
    id: "git-mirror-push",
    severity: "high",
    re: /\bgit\s+push\b[^\n]*--mirror\b|\bgit\s+filter-(?:branch|repo)\b/,
    description: "Mirror-push or history rewrite replaces the entire remote.",
  },
  {
    id: "schedule-wipe",
    severity: "high",
    re: /\bcrontab\s+-r\b|\bsystemctl\s+(?:disable|mask)\s+--now\b/,
    description: "Removing scheduled jobs or disabling services.",
  },
  {
    id: "secure-erase",
    severity: "high",
    re: /\bshred\b[^\n]*-[a-zA-Z]*u|\bwipe\s+-\w|\btruncate\s+-s\s*0\b/,
    description: "Unrecoverable file destruction (shred/truncate to zero).",
  },
  {
    id: "find-delete-broad",
    severity: "high",
    // `find . -delete` is fine; `find /` or `find ~` is not.
    re: /\bfind\s+(?:\/|~|\$HOME)\S*\s[^\n]*(?:-delete\b|-exec\s+rm\b)/,
    description: "Recursive find-and-delete rooted outside the project.",
  },
  {
    id: "firewall-flush",
    severity: "high",
    re: /\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b|\bufw\s+--force\s+reset\b/,
    description: "Flushing firewall rules removes network protection.",
  },
  {
    id: "repo-delete",
    severity: "high",
    re: /\bgh\s+repo\s+delete\b|\bglab\s+repo\s+delete\b/,
    description: "Deleting a remote repository.",
  },
  {
    id: "package-publish",
    severity: "high",
    // Publishing is irreversible and is a supply-chain action, not a local one.
    re: /\bnpm\s+publish\b|\byarn\s+publish\b|\bpnpm\s+publish\b|\btwine\s+upload\b|\bcargo\s+publish\b|\bgem\s+push\b/,
    description: "Publishing a package is irreversible and affects downstream users.",
  },
  {
    id: "curl-pipe-shell",
    severity: "high",
    re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|)sh\b/,
    description: "Piping a downloaded script straight into a shell.",
  },
];

export function analyzeDestructive(command: string): DestructiveFinding[] {
  const findings: DestructiveFinding[] = [];

  const rm = analyzeRm(command);
  if (rm) findings.push(rm);

  for (const r of RULES) {
    if (r.re.test(command)) {
      findings.push({ rule: r.id, severity: r.severity, description: r.description });
    }
  }
  return findings;
}
