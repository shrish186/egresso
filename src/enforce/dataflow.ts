// Data-flow (taint) analysis for shell commands. Content-scanning alone is easy to
// evade: an attacker base64/hex-encodes the secret, references it as $ENV_VAR, or
// exfiltrates over DNS — so the literal never appears in the command text. Instead we
// ask a structural question: does this command READ a secret SOURCE and also reach a
// network SINK? If both, it's an exfiltration path regardless of encoding.
//
// Before asking that question we NORMALIZE the command, because the source and the
// sink can both be hidden by ordinary shell syntax: `.e''nv`, `cat${IFS}.env`,
// `cat .*nv`, or `eval $(echo <base64> | base64 -d)`. Normalization is what makes the
// structural question hold up against an adversary who knows we are looking.

export type FlowFinding = {
  sources: string[]; // secret sources touched, e.g. ".env", "$ANTHROPIC_API_KEY"
  sink?: string; // the egress channel, e.g. "curl", "dns:nslookup", "/dev/tcp"
  staged?: string; // wrote a secret source to a path outside the project
};

// ---------------------------------------------------------------------------
// Normalization — undo the cheap syntactic tricks before analysis.
// ---------------------------------------------------------------------------

/** Filenames whose contents are secrets, used for glob resolution. */
const SECRET_BASENAMES = [
  ".env", ".env.local", ".env.production", ".env.development",
  "id_rsa", "id_ed25519", "id_ecdsa", "credentials", "config.json", "config",
  ".netrc", ".npmrc", ".pgpass", "server.pem", "key.p12", "cert.pfx",
];

/**
 * Decode base64 without assuming Node. The engine is deliberately free of
 * platform APIs so the same analysis runs in a browser playground, an edge
 * worker or Deno — not just behind the CLI.
 */
function decodeBase64(b64: string): string | null {
  try {
    const g = globalThis as { atob?: (s: string) => string; Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } };
    if (typeof g.atob === "function") return g.atob(b64);
    if (g.Buffer) return g.Buffer.from(b64, "base64").toString("utf8");
  } catch {
    /* malformed base64 */
  }
  return null;
}

/** Does a shell glob token resolve to something secret-bearing? */
function globMatchesSecret(token: string): boolean {
  if (!/[*?\[]/.test(token)) return false;
  const base = token.split("/").pop() ?? token;
  // Translate the glob to a regex: * -> .*, ? -> ., leave other chars literal.
  const rx = new RegExp(
    "^" + base.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
    "i"
  );
  return SECRET_BASENAMES.some((n) => rx.test(n));
}

export function normalize(command: string): string {
  let s = command;

  // 1. ${IFS} / $IFS field-separator smuggling: cat${IFS}.env
  s = s.replace(/\$\{IFS\}|\$IFS/g, " ");

  // 2. Quote-splitting inside a word: .e''nv -> .env, cat "" .env
  //    Only collapse EMPTY quote pairs; real quoted strings must survive.
  s = s.replace(/''|""/g, "");

  // 3. Inline base64 payloads that get decoded and executed:
  //    eval $(echo 'Y2F0IC5lbnY=' | base64 -d)
  //    Decode the literal and append it so its contents are analyzed too.
  for (const m of s.matchAll(/['"]?([A-Za-z0-9+/=]{8,})['"]?\s*\|\s*(?:openssl\s+)?base64\s+(?:-d|-D|--decode)/g)) {
    const decoded = decodeBase64(m[1]);
    if (decoded && /^[\x20-\x7e\s]+$/.test(decoded)) s += " ; " + decoded;
  }

  // 4. ANSI-C quoting: $'\x2eenv' -> .env
  s = s.replace(/\$'((?:[^'\\]|\\.)*)'/g, (_, body: string) =>
    body
      .replace(/\\x([0-9a-fA-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\0?([0-7]{1,3})/g, (_m, o) => String.fromCharCode(parseInt(o, 8)))
  );

  // 5. printf-constructed filenames: cat $(printf '.env')
  s = s.replace(/\$\(\s*printf\s+['"]([^'"]*)['"]\s*\)/g, "$1");

  // 6. Simple variable assignments, so `x=e; cat ".${x}nv"` resolves. One pass
  //    only — this is evasion-undoing, not a shell interpreter.
  const vars = new Map<string, string>();
  for (const m of s.matchAll(/(?:^|[;&|(]\s*)([A-Za-z_]\w*)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]+))/g)) {
    vars.set(m[1], m[2] ?? m[3] ?? m[4] ?? "");
  }
  if (vars.size) {
    s = s.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (whole, name) => vars.get(name) ?? whole);
  }

  // 7. Globs that resolve to secret files: cat .*nv -> mark as .env
  s = s.replace(/(^|\s)([^\s|;&<>]*[*?][^\s|;&<>]*)/g, (whole, pre, tok) =>
    globMatchesSecret(tok) ? `${pre}${tok} .env` : whole
  );

  // 8. Shadow copies with quoting and escaping removed, appended rather than
  //    substituted so both the original and the de-quoted form are searchable.
  //    Catches `"."env` and `.e\nv`, which are the same file to the shell.
  const dequoted = s.replace(/['"]/g, "");
  const unescaped = s.replace(/\\(.)/g, "$1");
  if (dequoted !== s) s += " ; " + dequoted;
  if (unescaped !== s) s += " ; " + unescaped;

  return s;
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

// Files whose contents are secrets. The leading class includes `@` so that curl's
// file-attach syntax (`--data-binary @.env`) is recognized as a read, and `~`/`.`
// so that `~/.aws/credentials` matches on the path segment.
// `.env.example` / `.env.sample` / `.env.template` are committed placeholders with
// no live credentials in them — treating them as secrets is a false positive that
// fires on the most common onboarding command there is (`cp .env.example .env`).
const SECRET_FILE =
  /(^|[\s'"=<|/@~])(\.env(?!\.(?:example|sample|template|dist|default|tpl|schema)\b)(?:\.[\w.-]+)?|id_rsa|id_ed25519|id_ecdsa|[\w.-]*\.(?:pem|p12|pfx|key)|credentials|\.netrc|\.npmrc|\.pgpass|\.htpasswd)\b/gi;

// Whole directories/files that are credential stores. Matched as paths, so that
// `rsync ~/.ssh/ host:` and `tar czf b.tgz ~/.aws` both count as reads.
const SECRET_PATH =
  /(\.ssh\/?|\.aws\/(?:credentials|config)?|\.aws\b|\.kube\/config|\.kube\b|\.docker\/config\.json|\.docker\b|\.gnupg\b|\.config\/gcloud\b|\.git-credentials|\.pypirc|\.cargo\/credentials(?:\.toml)?|\.m2\/settings\.xml|\.config\/gh\/hosts\.ya?ml|\.terraformrc|terraform\.tfstate|\.kaggle\/kaggle\.json|\.config\/hub|\.bundle\/config|\.gem\/credentials|\.databrickscfg|\.snowflake|\.oci\/config|\/proc\/self\/environ|\/proc\/\d+\/environ)/gi;

// Commands that PRINT a credential rather than reading a file. The secret never
// touches disk, so path matching alone cannot see it — the verb is the source.
const SECRET_COMMAND: { re: RegExp; label: string }[] = [
  { re: /\bkubectl\s+get\s+secrets?\b[^\n]*(-o|--output)\s*[= ]?\s*(yaml|json|jsonpath)/, label: "kubectl secret values" },
  { re: /\bsecurity\s+find-(?:generic|internet)-password\b[^\n]*-w/, label: "macOS keychain" },
  { re: /\bgcloud\s+auth\s+(?:print-access-token|print-identity-token)\b/, label: "gcloud token" },
  { re: /\baws\s+configure\s+get\b|\baws\s+sts\s+get-session-token\b/, label: "aws credentials" },
  { re: /\bdocker\s+inspect\b/, label: "docker inspect (container env)" },
  { re: /\bhelm\s+get\s+values\b/, label: "helm values" },
  { re: /\bps\s+e?\s*(?:ww?|aux)?\s*e\b|\bps\s+eww?\b/, label: "process environment" },
  { re: /\bgit\s+config\b[^\n]*\b(?:user\.password|credential)\b/, label: "git credential config" },
  { re: /\bvault\s+(?:read|kv\s+get)\b/, label: "vault secret" },
  { re: /\bop\s+(?:read|item\s+get)\b/, label: "1password secret" },
  { re: /\bcat\s+[^\n|]*\.tfstate\b/, label: "terraform state" },
];

// A reference to an environment variable whose name looks secret-bearing.
// Covers shell ($X, ${X}), Python (os.environ["X"], os.getenv("X")) and
// Node (process.env.X) so that `-c` / `-e` interpreter bodies are analyzed.
const SECRET_ENVVAR =
  /(?:\$\{?|process\.env\.|os\.environ\[['"]|os\.environ\.get\(['"]|os\.getenv\(['"]|ENV\[['"])([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|AUTH)[A-Z0-9_]*)/g;

// Commands that dump the WHOLE environment — which necessarily includes any
// secret-bearing variable, so the command itself is a secret source.
const ENV_DUMP = /(^|[\s;|&(])(printenv|env|set|export\s*-p|declare\s+-x)\s*(?=[\s;|&)]|$)/;

// Introducing a new git remote makes the whole working tree exfiltratable: the
// next `git push` ships every file in the repository to whoever owns that URL.
// The repo is the source; the destination allowlist decides whether it is okay.
const GIT_REMOTE_ADD = /\bgit\s+remote\s+(?:add|set-url)\s+\S+\s+(\S+)/;

// Commands that read/emit file contents into a pipeline (so `cat .env | ...` counts
// the .env even though the network verb is later in the pipe).
const READERS = /\b(cat|head|tail|less|more|xxd|od|base64|base32|openssl|gpg|tr|rev|strings|dd|cp|mv|tee|tar|zip|gzip|uuencode)\b/;

function findSecretSources(command: string): string[] {
  const sources = new Set<string>();
  let m: RegExpExecArray | null;

  SECRET_FILE.lastIndex = 0;
  while ((m = SECRET_FILE.exec(command)) !== null) sources.add(m[2]);

  SECRET_PATH.lastIndex = 0;
  while ((m = SECRET_PATH.exec(command)) !== null) sources.add(m[1].replace(/\/$/, ""));

  SECRET_ENVVAR.lastIndex = 0;
  while ((m = SECRET_ENVVAR.exec(command)) !== null) sources.add(`$${m[1]}`);

  if (ENV_DUMP.test(command)) sources.add("environment (full dump)");

  for (const { re, label } of SECRET_COMMAND) if (re.test(command)) sources.add(label);

  // A freshly-added remote only matters if something then pushes to it.
  if (GIT_REMOTE_ADD.test(command) && /\bgit\s+push\b/.test(command)) {
    sources.add("repository contents");
  }

  return [...sources];
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

const SINKS: { re: RegExp; label: string }[] = [
  { re: /\bcurl\b/, label: "curl" },
  { re: /\bwget\b/, label: "wget" },
  { re: /\bnc\b|\bncat\b|\bnetcat\b|\bsocat\b/, label: "netcat/socat" },
  { re: /\/dev\/tcp\/|\/dev\/udp\//, label: "/dev/tcp" },
  { re: /\bnslookup\b|\bdig\b|\bhost\b|\bdrill\b/, label: "dns" },
  { re: /\bping\b[^\n]*\s-p\s/, label: "icmp-payload" },
  { re: /\bssh\b|\bscp\b|\bsftp\b|\brsync\b/, label: "ssh/scp" },
  { re: /\bpython3?\b[^\n]*\b(urllib|requests|http\.client|socket)\b/, label: "python-http" },
  { re: /\bnode\b[^\n]*\b(fetch|http|https|net\.)\b/, label: "node-http" },
  { re: /\b(perl|ruby|php)\b[^\n]*\b(LWP|Net::|open-uri|net\/http|file_get_contents|curl_)\b/i, label: "interpreter-http" },
  { re: /\bgit\s+push\b/, label: "git-push" },
  { re: /\bmail\b|\bsendmail\b|\bmutt\b/, label: "mail" },
  // Egress channels that are not obviously "the network".
  { re: /\bpbcopy\b|\bxclip\b|\bxsel\b|\bclip\.exe\b/, label: "clipboard" },
  { re: /(^|[\s;|&])https?\s+(?:--?\w+\s+)*(?:POST|PUT|GET|PATCH)\b|(^|[\s;|&])http\s+\S+\.\S+/, label: "httpie" },
  { re: /\blftp\b|\bftp\b|\btelnet\b|\bcurlftpfs\b/, label: "ftp/telnet" },
  { re: /\b(?:open|xdg-open|start)\s+["']?https?:\/\//, label: "browser" },
  { re: /\baws\s+s3\s+(?:cp|sync|mv)\b[^\n]*s3:\/\//, label: "s3-upload" },
  { re: /\bgh\s+gist\s+create\b|\bgh\s+release\s+upload\b/, label: "gh-publish" },
  { re: /\bpython3?\s+-m\s+http\.server\b|\bnpx\s+serve\b|\bphp\s+-S\b/, label: "local-http-server" },
  { re: /\b(?:gsutil|az\s+storage\s+blob)\s+(?:cp|upload)\b/, label: "cloud-upload" },
];

function findSink(command: string): string | undefined {
  for (const { re, label } of SINKS) if (re.test(command)) return label;
  return undefined;
}

// Paths that count as "outside the project" — staging a secret there is a leak even
// with no network verb (a later step, or the attacker, picks it up). Web-served
// roots are the worst case: staging there publishes the secret immediately.
const EXTERNAL_PATH =
  /(^|\s|>)(\/tmp\/|\/var\/tmp\/|\/private\/tmp\/|\/var\/www\/|\/usr\/share\/nginx\/|\/srv\/http\/|\/public\/|~\/(?!\.config)|\/Users\/[^/]+\/(?:Public|Downloads)\/)/;

// ---------------------------------------------------------------------------

/**
 * Secret sources referenced anywhere in a blob of text, with normalization applied.
 *
 * For a shell command the sink is a verb we can name (`curl`, `nc`, DNS). For an MCP
 * tool call there is no verb — the call itself IS the egress — so callers on that path
 * need the sources alone and supply the destination themselves.
 */
export function secretSourcesIn(text: string): string[] {
  return findSecretSources(normalize(text));
}

/** Analyze one shell command for a source→sink exfiltration path. */
export function analyzeFlow(command: string): FlowFinding | null {
  const cmd = normalize(command);

  const sources = findSecretSources(cmd);
  if (sources.length === 0) return null;

  const sink = findSink(cmd);
  if (sink) return { sources, sink };

  // No network verb, but a reader is moving a secret file to an external path.
  if (READERS.test(cmd) && EXTERNAL_PATH.test(cmd)) {
    const dest = cmd.match(EXTERNAL_PATH);
    return { sources, staged: dest ? dest[0].trim() : "external path" };
  }

  // Redirection of a secret into a world-readable location, e.g. `cat .env >> /var/www/...`
  if (/>>?\s*\S/.test(cmd) && EXTERNAL_PATH.test(cmd)) {
    const dest = cmd.match(EXTERNAL_PATH);
    return { sources, staged: dest ? dest[0].trim() : "external path" };
  }

  return null;
}
