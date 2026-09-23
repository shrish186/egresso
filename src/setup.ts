// `egresso init` and `egresso doctor`. init wires the PreToolUse hook into
// .claude/settings.json (merging, not clobbering) and writes a starter config.
// doctor verifies the setup so users can confirm enforcement is actually live.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const HOOK_CMD = "npx egresso hook";

const STARTER_CONFIG = {
  mode: "block",
  allowedDestinations: ["api.openai.com", "api.anthropic.com"],
  destructive: { high: "block", medium: "ask" },
  customRules: [
    { id: "example-no-prod-deploy", pattern: "deploy .*--env[= ]prod", action: "ask", message: "Production deploy — confirm first." },
  ],
};

type Settings = {
  hooks?: {
    PreToolUse?: { matcher?: string; hooks?: { type: string; command: string }[] }[];
    [k: string]: unknown;
  };
  [k: string]: unknown;
};

export function runInit(cwd = process.cwd()): void {
  // 1. Starter config.
  const cfgPath = join(cwd, "egresso.config.json");
  if (existsSync(cfgPath)) {
    console.log(`• egresso.config.json already exists — left as is.`);
  } else {
    writeFileSync(cfgPath, JSON.stringify(STARTER_CONFIG, null, 2) + "\n");
    console.log(`✓ wrote egresso.config.json`);
  }

  // 2. Merge the hook into .claude/settings.json.
  const claudeDir = join(cwd, ".claude");
  const settingsPath = join(claudeDir, "settings.json");
  let settings: Settings = {};
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, "utf8")) as Settings;
    } catch {
      console.log(`⚠ .claude/settings.json isn't valid JSON — add the hook manually.`);
      return;
    }
  } else {
    mkdirSync(claudeDir, { recursive: true });
  }

  settings.hooks ??= {};
  settings.hooks.PreToolUse ??= [];
  const already = settings.hooks.PreToolUse.some((m) =>
    m.hooks?.some((h) => h.command?.includes("egresso"))
  );
  if (already) {
    console.log(`• PreToolUse hook already references egresso — left as is.`);
  } else {
    settings.hooks.PreToolUse.push({ matcher: "Bash", hooks: [{ type: "command", command: HOOK_CMD }] });
    writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    console.log(`✓ added PreToolUse hook to .claude/settings.json`);
  }
  console.log(`\nEnforcement is live. Run 'egresso doctor' to verify, 'egresso log' to watch decisions.`);
}

export function runDoctor(cwd = process.cwd()): void {
  let ok = true;
  const check = (label: string, pass: boolean, hint?: string) => {
    console.log(`${pass ? "✓" : "✗"} ${label}`);
    if (!pass && hint) console.log(`    ${hint}`);
    if (!pass) ok = false;
  };

  const settingsPath = join(cwd, ".claude", "settings.json");
  let hookWired = false;
  if (existsSync(settingsPath)) {
    try {
      const s = JSON.parse(readFileSync(settingsPath, "utf8")) as Settings;
      hookWired = !!s.hooks?.PreToolUse?.some((m) => m.hooks?.some((h) => h.command?.includes("egresso")));
    } catch {
      /* leave hookWired false */
    }
  }
  check("PreToolUse hook wired in .claude/settings.json", hookWired, "run 'egresso init'");
  check("egresso.config.json present", existsSync(join(cwd, "egresso.config.json")), "run 'egresso init' (optional; zero-config also works)");

  const envFiles = [".env", ".env.local"].filter((f) => existsSync(join(cwd, f)));
  check(
    `secret source detected (${envFiles.length ? envFiles.join(", ") : "none in cwd"})`,
    true,
    envFiles.length ? undefined : "no .env here — egresso still catches known key formats + high-entropy tokens"
  );

  console.log(ok ? "\nAll good — egresso is set up." : "\nSome checks failed — see hints above.");
}
