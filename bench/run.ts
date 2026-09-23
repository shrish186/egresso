// egresso benchmark runner.
//
//   npm run bench           full report
//   npm run bench -- --json write bench/results.json
//   npm run bench -- --fail show every miss and false positive
//
// Two tiers, reported separately and on purpose:
//
//   tier 1 (corpus.ts)      the detector was FIXED against these. A high score
//                           here proves the loop closed, nothing more.
//   tier 2 (corpus-hard.ts) written to break the current implementation using
//                           techniques the fixes did not consider. This is the
//                           number that means something.
//
// Reporting only tier 1 would be dishonest, so the summary leads with tier 2.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { CORPUS, type Case } from "./corpus.js";
import { HARD_CORPUS } from "./corpus-hard.js";
import { ENGINES, type Engine } from "./engines.js";

type Miss = { id: string; technique: string; cmd: string; note?: string };

type Result = {
  engine: string;
  approach: string;
  blockRate: number;
  passRate: number;
  balanced: number;
  attacksTotal: number;
  benignTotal: number;
  medianUs: number;
  misses: Miss[];
  falsePositives: Miss[];
  byTechnique: Record<string, { hit: number; total: number }>;
};

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const pad = (s: string, n: number) => s.padEnd(n);
const padL = (s: string, n: number) => s.padStart(n);

function evaluate(engine: Engine, corpus: Case[]): Result {
  const timings: number[] = [];
  const misses: Miss[] = [];
  const falsePositives: Miss[] = [];
  const byTechnique: Record<string, { hit: number; total: number }> = {};

  for (const c of corpus) {
    const t0 = process.hrtime.bigint();
    let verdict: "block" | "allow";
    try {
      verdict = engine.run(c.cmd);
    } catch {
      verdict = c.expected === "block" ? "allow" : "block"; // a crash is a failure
    }
    timings.push(Number(process.hrtime.bigint() - t0) / 1000);

    const correct = verdict === c.expected;
    byTechnique[c.technique] ??= { hit: 0, total: 0 };
    byTechnique[c.technique].total++;
    if (correct) byTechnique[c.technique].hit++;
    else (c.expected === "block" ? misses : falsePositives).push({ id: c.id, technique: c.technique, cmd: c.cmd, note: c.note });
  }

  const attacksTotal = corpus.filter((c) => c.expected === "block").length;
  const benignTotal = corpus.length - attacksTotal;
  const blockRate = (attacksTotal - misses.length) / attacksTotal;
  const passRate = (benignTotal - falsePositives.length) / benignTotal;

  timings.sort((a, b) => a - b);

  return {
    engine: engine.name,
    approach: engine.approach,
    blockRate,
    passRate,
    balanced: (blockRate + passRate) / 2,
    attacksTotal,
    benignTotal,
    medianUs: timings[Math.floor(timings.length / 2)],
    misses,
    falsePositives,
    byTechnique,
  };
}

function table(title: string, note: string, corpus: Case[], results: Result[]) {
  const a = corpus.filter((c) => c.expected === "block").length;
  console.log(`\n\x1b[1m${title}\x1b[0m  —  ${corpus.length} cases (${a} attacks, ${corpus.length - a} benign)`);
  console.log(`\x1b[2m${note}\x1b[0m\n`);
  console.log(`  ${pad("engine", 18)}${padL("attacks", 9)}${padL("benign", 9)}${padL("balanced", 10)}${padL("median", 9)}`);
  console.log(`  ${"-".repeat(55)}`);
  for (const r of results) {
    const dim = r.engine === "block-everything" ? "\x1b[2m" : "";
    console.log(
      `  ${dim}${pad(r.engine, 18)}${padL(pct(r.blockRate), 9)}${padL(pct(r.passRate), 9)}` +
        `${padL(pct(r.balanced), 10)}${padL(`${r.medianUs.toFixed(0)}µs`, 9)}\x1b[0m`
    );
  }
}

// --------------------------------------------------------------------------

const showFailures = process.argv.includes("--fail");
const writeJson = process.argv.includes("--json");

const tier1 = ENGINES.map((e) => evaluate(e, CORPUS));
const tier2 = ENGINES.map((e) => evaluate(e, HARD_CORPUS));

console.log(`\n\x1b[1megresso adversarial benchmark\x1b[0m`);

table("TIER 1 — known corpus", "the detector was fixed against these; treat a high score as overfit", CORPUS, tier1);
table("TIER 2 — held out", "written to break the current implementation; THIS is the honest number", HARD_CORPUS, tier2);

// Per-technique, tier 2 only — that is where the information is.
const real2 = tier2.filter((r) => r.engine !== "block-everything");
const techniques = [...new Set(HARD_CORPUS.map((c) => c.technique))];
console.log(`\n\x1b[1mTier 2 by technique\x1b[0m  (correct / total)\n`);
console.log(`  ${pad("technique", 20)}${real2.map((r) => padL(r.engine, 18)).join("")}`);
console.log(`  ${"-".repeat(20 + real2.length * 18)}`);
for (const t of techniques) {
  const cells = real2.map((r) => {
    const s = r.byTechnique[t];
    const txt = `${s.hit}/${s.total}`;
    const perfect = s.hit === s.total;
    return padL(perfect ? txt : `\x1b[33m${txt}\x1b[0m`, perfect ? 18 : 27);
  });
  console.log(`  ${pad(t, 20)}${cells.join("")}`);
}

const e2 = tier2.find((r) => r.engine === "egresso")!;
const b2 = tier2.find((r) => r.engine === "regex-baseline")!;
console.log(`\n\x1b[1mHeld-out head-to-head\x1b[0m\n`);
console.log(`  egresso        ${pct(e2.balanced)} balanced   (${e2.misses.length} missed, ${e2.falsePositives.length} false positives)`);
console.log(`  regex-baseline ${pct(b2.balanced)} balanced   (${b2.misses.length} missed, ${b2.falsePositives.length} false positives)`);

if (showFailures) {
  for (const [label, rs] of [["TIER 1", tier1], ["TIER 2", tier2]] as const) {
    for (const r of rs.filter((x) => x.engine === "egresso")) {
      if (!r.misses.length && !r.falsePositives.length) continue;
      console.log(`\n\x1b[1m${label} — egresso failures\x1b[0m`);
      for (const m of r.misses) console.log(`  \x1b[31mMISS\x1b[0m ${pad(m.id, 10)} ${m.cmd.slice(0, 70)}`);
      for (const m of r.falsePositives) console.log(`  \x1b[33mFP  \x1b[0m ${pad(m.id, 10)} ${m.cmd.slice(0, 70)}`);
    }
  }
}

console.log();

if (writeJson) {
  const out = join(import.meta.dirname, "results.json");
  writeFileSync(out, JSON.stringify({ generatedAt: new Date().toISOString(), tier1, tier2 }, null, 2));
  console.log(`  wrote ${out}\n`);
}

process.exit(0);
