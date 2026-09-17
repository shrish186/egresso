// Secret detection: finds credentials in text that an agent is about to send out.
// Two layers: (1) known-token regexes, (2) high-entropy strings, (3) values loaded
// from the project's own .env files (the strongest signal — these are *your* secrets).

export type SecretHit = {
  kind: string; // e.g. "aws-access-key", "env:OPENAI_API_KEY", "high-entropy"
  match: string; // the raw matched substring
  redacted: string; // safe-to-log version
  index: number; // position in the scanned text
};

// Well-known credential formats. Kept deliberately tight to limit false positives.
const PATTERNS: { kind: string; re: RegExp }[] = [
  { kind: "aws-access-key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "openai-key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { kind: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { kind: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { kind: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { kind: "stripe-key", re: /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g },
  { kind: "private-key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { kind: "bearer", re: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g },
];

export function redact(s: string): string {
  if (s.length <= 8) return "*".repeat(s.length);
  return `${s.slice(0, 3)}…${s.slice(-2)} (${s.length} chars)`;
}

// Shannon entropy in bits/char — high for random tokens, low for prose.
export function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export type ScanOptions = {
  // Exact secret values loaded from the environment/.env. Highest-confidence matches.
  knownValues?: Map<string, string>; // value -> label (e.g. "OPENAI_API_KEY")
  entropyThreshold?: number; // default 4.0 bits/char
  minEntropyLen?: number; // default 20
};

const HIGH_ENTROPY_TOKEN = /\b[A-Za-z0-9+/_=-]{20,}\b/g;

export function scan(text: string, opts: ScanOptions = {}): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<number>(); // start indices already claimed, to avoid dupes

  // (1) Exact known values from .env — the strongest signal.
  if (opts.knownValues) {
    for (const [value, label] of opts.knownValues) {
      if (value.length < 6) continue; // skip trivially short env values
      let i = text.indexOf(value);
      while (i !== -1) {
        hits.push({ kind: `env:${label}`, match: value, redacted: redact(value), index: i });
        seen.add(i);
        i = text.indexOf(value, i + value.length);
      }
    }
  }

  // (2) Known token formats.
  for (const { kind, re } of PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (seen.has(m.index)) continue;
      hits.push({ kind, match: m[0], redacted: redact(m[0]), index: m.index });
      seen.add(m.index);
    }
  }

  // (3) High-entropy fallback for tokens we don't recognize by shape.
  const thr = opts.entropyThreshold ?? 4.0;
  const minLen = opts.minEntropyLen ?? 20;
  HIGH_ENTROPY_TOKEN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HIGH_ENTROPY_TOKEN.exec(text)) !== null) {
    if (seen.has(m.index)) continue;
    const tok = m[0];
    if (tok.length >= minLen && entropy(tok) >= thr) {
      hits.push({ kind: "high-entropy", match: tok, redacted: redact(tok), index: m.index });
      seen.add(m.index);
    }
  }

  return hits.sort((a, b) => a.index - b.index);
}
