// Second failure mode: destructive actions. Agents given shell access can wipe
// files, force-push over history, drop databases, or delete cloud/k8s resources —
// often triggered by a confused plan or a prompt injection, not malice. We flag the
// high-blast-radius ones so they can be blocked or sent for human approval.

export type DestructiveFinding = {
  rule: string; // stable id, e.g. "rm-rf-root"
  severity: "high" | "medium";
  description: string;
};

type Rule = { id: string; severity: "high" | "medium"; re: RegExp; description: string };

const RULES: Rule[] = [
  {
    id: "rm-rf-root",
    severity: "high",
    re: /\brm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*(?:\/|~|\/\*|\$HOME|\.\s*$|\*\s*$)/,
    description: "Recursive force-delete of a root/home/wildcard path.",
  },
  {
    id: "rm-rf-generic",
    severity: "medium",
    re: /\brm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*r[a-zA-Z]*f?[a-zA-Z]*\b/,
    description: "Recursive delete (rm -r). Review the target path.",
  },
  {
    id: "git-force-push",
    severity: "high",
    re: /\bgit\s+push\b[^\n]*(?:--force\b|\s-f\b)(?![-\w])/,
    description: "Force-push can overwrite remote history for everyone.",
  },
  {
    id: "git-hard-reset",
    severity: "medium",
    re: /\bgit\s+reset\s+--hard\b/,
    description: "Hard reset discards uncommitted work.",
  },
  {
    id: "git-clean",
    severity: "medium",
    re: /\bgit\s+clean\b[^\n]*-[a-zA-Z]*[dfx]/,
    description: "git clean -df permanently removes untracked files.",
  },
  {
    id: "db-drop",
    severity: "high",
    re: /\b(DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE?|DELETE\s+FROM\s+\w+\s*(?:;|$))/i,
    description: "Destructive SQL: drop/truncate/unfiltered delete.",
  },
  {
    id: "k8s-delete",
    severity: "high",
    re: /\bkubectl\s+delete\b|\bhelm\s+(?:delete|uninstall)\b/,
    description: "Deleting Kubernetes/Helm resources.",
  },
  {
    id: "cloud-destroy",
    severity: "high",
    re: /\bterraform\s+destroy\b|\baws\s+\w+\s+(?:delete|terminate|remove)-|\bgcloud\s+\w+\s+delete\b/,
    description: "Tearing down cloud infrastructure.",
  },
  {
    id: "disk-write",
    severity: "high",
    re: /\b(?:dd\s+[^\n]*of=\/dev\/|mkfs\.[a-z0-9]+\s+\/dev\/|>\s*\/dev\/sd[a-z])/,
    description: "Writing directly to a block device wipes it.",
  },
  {
    id: "chmod-recursive-777",
    severity: "medium",
    re: /\bchmod\s+-R\s+0?777\b/,
    description: "Recursively world-writable permissions.",
  },
  {
    id: "fork-bomb",
    severity: "high",
    re: /:\(\)\s*\{\s*:\|:&\s*\}\s*;/,
    description: "Shell fork bomb.",
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
  for (const r of RULES) {
    if (r.re.test(command)) {
      findings.push({ rule: r.id, severity: r.severity, description: r.description });
    }
  }
  return findings;
}
