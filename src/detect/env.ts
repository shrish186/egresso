// Loads the project's own secrets from .env files so we can detect exact-value
// leaks. This is what makes agentwall "know your secrets" rather than guessing.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const ENV_FILES = [".env", ".env.local", ".env.development", ".env.production"];

// Parse KEY=VALUE lines. Deliberately simple; ignores comments and blanks.
function parseEnvFile(content: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim().replace(/^export\s+/, "");
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (key && val) out.set(val, key); // value -> label
  }
  return out;
}

// Returns a map of secret value -> label, drawn from .env files in `cwd` plus
// the live process environment (so exported keys are caught too).
export function loadKnownSecrets(cwd = process.cwd()): Map<string, string> {
  const known = new Map<string, string>();
  for (const f of ENV_FILES) {
    const p = join(cwd, f);
    if (existsSync(p)) {
      try {
        for (const [v, k] of parseEnvFile(readFileSync(p, "utf8"))) known.set(v, k);
      } catch {
        /* unreadable file — skip */
      }
    }
  }
  // Live env: only values that look secret-ish by key name, to avoid flagging PATH etc.
  const SECRETISH = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API|AUTH)/i;
  for (const [k, v] of Object.entries(process.env)) {
    if (v && v.length >= 8 && SECRETISH.test(k)) known.set(v, k);
  }
  return known;
}
