// Data-flow (taint) analysis for shell commands. Content-scanning alone is easy to
// evade: an attacker base64/hex-encodes the secret, references it as $ENV_VAR, or
// exfiltrates over DNS — so the literal never appears in the command text. Instead we
// ask a structural question: does this command READ a secret SOURCE and also reach a
// network SINK? If both, it's an exfiltration path regardless of encoding.

export type FlowFinding = {
  sources: string[]; // secret sources touched, e.g. ".env", "$ANTHROPIC_API_KEY"
  sink?: string; // the egress channel, e.g. "curl", "dns:nslookup", "/dev/tcp"
  staged?: string; // wrote a secret source to a path outside the project
};

// Files whose contents are secrets. Matches reads like `cat .env`, `< .env`, `.env.local`.
const SECRET_FILE = /(^|[\s'"=<|/])(\.env(?:\.[\w.-]+)?|(?:id_rsa|id_ed25519|\.pem|\.p12|\.pfx|credentials|\.netrc|\.npmrc|\.pgpass))\b/gi;

// A reference to an environment variable whose name looks secret-bearing.
const SECRET_ENVVAR = /\$\{?([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|AUTH)[A-Z0-9_]*)\}?/g;

// Commands that read/emit file contents into a pipeline (so `cat .env | ...` counts
// the .env even though the network verb is later in the pipe).
const READERS = /\b(cat|head|tail|less|more|xxd|od|base64|openssl|gpg|tr|rev|strings|dd|cp|mv|tee)\b/;

// Network egress sinks. DNS tools included because DNS exfil needs no http/nc.
const SINKS: { re: RegExp; label: string }[] = [
  { re: /\bcurl\b/, label: "curl" },
  { re: /\bwget\b/, label: "wget" },
  { re: /\bnc\b|\bncat\b|\bnetcat\b/, label: "netcat" },
  { re: /\/dev\/tcp\//, label: "/dev/tcp" },
  { re: /\bnslookup\b|\bdig\b|\bhost\b/, label: "dns" },
  { re: /\bssh\b|\bscp\b|\bsftp\b|\brsync\b/, label: "ssh/scp" },
  { re: /\bpython3?\b.*\b(urllib|requests|http)\b/, label: "python-http" },
  { re: /\bnode\b.*\b(fetch|http|https)\b/, label: "node-http" },
];

// Paths that count as "outside the project" — staging a secret there is a leak even
// with no network verb (a later step, or the attacker, picks it up).
const EXTERNAL_PATH = /(^|\s)(\/tmp\/|\/var\/tmp\/|\/private\/tmp\/|~\/(?!\.config)|\/Users\/[^/]+\/(?:Public|Downloads)\/)/;

function findSecretSources(command: string): string[] {
  const sources = new Set<string>();
  let m: RegExpExecArray | null;

  SECRET_FILE.lastIndex = 0;
  while ((m = SECRET_FILE.exec(command)) !== null) sources.add(m[2]);

  SECRET_ENVVAR.lastIndex = 0;
  while ((m = SECRET_ENVVAR.exec(command)) !== null) sources.add(`$${m[1]}`);

  return [...sources];
}

function findSink(command: string): string | undefined {
  for (const { re, label } of SINKS) if (re.test(command)) return label;
  return undefined;
}

// Analyze one shell command for a source→sink exfiltration path.
export function analyzeFlow(command: string): FlowFinding | null {
  const sources = findSecretSources(command);
  if (sources.length === 0) return null;

  const sink = findSink(command);
  if (sink) return { sources, sink };

  // No network verb, but a reader is moving a secret file to an external path.
  if (READERS.test(command) && EXTERNAL_PATH.test(command)) {
    const dest = command.match(EXTERNAL_PATH);
    return { sources, staged: dest ? dest[0].trim() : "external path" };
  }

  return null;
}
