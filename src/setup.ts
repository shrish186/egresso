// `egresso init` and `egresso doctor`. init wires the PreToolUse hook into
// .claude/settings.json (merging, not clobbering) and writes a starter config.
// doctor verifies the setup so users can confirm enforcement is actually live.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { loadConfig } from "./config.js";

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

  // Enforcement can be wired per-project OR for the whole user. Checking only the
  // project made a correct user-level install report as broken.
  const hookedIn = (settingsPath: string): boolean => {
    if (!existsSync(settingsPath)) return false;
    try {
      const s = JSON.parse(readFileSync(settingsPath, "utf8")) as Settings;
      return !!s.hooks?.PreToolUse?.some((m) => m.hooks?.some((h) => h.command?.includes("egresso")));
    } catch {
      return false;
    }
  };
  const projectHook = hookedIn(join(cwd, ".claude", "settings.json"));
  const userHook = hookedIn(join(homedir(), ".claude", "settings.json"));
  const where = projectHook && userHook ? "project + user" : projectHook ? "this project" : userHook ? "user-wide" : "";
  check(
    `PreToolUse hook wired${where ? ` (${where})` : ""}`,
    projectHook || userHook,
    "run 'egresso init' here, or add the hook to ~/.claude/settings.json for every project"
  );

  const projectCfg = ["egresso.config.json", ".egresso.json"].find((f) => existsSync(join(cwd, f)));
  const userCfg = [join(homedir(), ".egresso.json"), join(homedir(), ".config", "egresso", "config.json")].find(existsSync);
  const cfg = loadConfig(cwd);
  check(
    `config loaded (${projectCfg ? projectCfg : userCfg ? userCfg.replace(homedir(), "~") : "zero-config defaults"})`,
    true,
    projectCfg || userCfg ? undefined : "zero-config works: any secret egress to a non-allowlisted host is blocked"
  );

  // The single most important thing to surface: in warn mode nothing is actually
  // stopped. Someone who forgets that believes they are protected when they are not.
  if (cfg.mode === "warn") {
    console.log(`\n⚠ mode: WARN — violations are logged but NOT blocked.`);
    console.log(`    audit log: ${(cfg.logFile ?? join(cwd, ".egresso/audit.jsonl")).replace("~", "~")}`);
    console.log(`    switch to enforcing by removing "mode" from your config.`);
  }

  const envFiles = [".env", ".env.local"].filter((f) => existsSync(join(cwd, f)));
  check(
    `secret source detected (${envFiles.length ? envFiles.join(", ") : "none in cwd"})`,
    true,
    envFiles.length ? undefined : "no .env here — egresso still catches known key formats + high-entropy tokens"
  );

  console.log(ok ? "\nAll good — egresso is set up." : "\nSome checks failed — see hints above.");
}
