// egresso benchmark runner.
//
//   npm run bench           full report
//   npm run bench -- --json write bench/results.json
//   npm run bench -- --fail show every miss and false positive
//
// Reports attack block rate AND benign pass rate together, always. A tool that
// blocks everything gets a perfect attack score, which is why the report
// includes `block-everything` as a control and leads with balanced accuracy.

import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { CORPUS, ATTACKS, BENIGN, type Case } from "./corpus.js";
import { ENGINES, type Engine } from "./engines.js";

type Miss = { id: string; technique: string; cmd: string; note?: string };

type Result = {
  engine: string;
  approach: string;
  attacksBlocked: number;
  attacksTotal: number;
  benignAllowed: number;
  benignTotal: number;
  blockRate: number;
  passRate: number;
  balanced: number;
  medianUs: number;
  p95Us: number;
  misses: Miss[];
  falsePositives: Miss[];
  byTechnique: Record<string, { hit: number; total: number }>;
};

const pct = (n: number) => `${(n * 100).toFixed(1)}%`;
const pad = (s: string, n: number) => s.padEnd(n);
const padL = (s: string, n: number) => s.padStart(n);

function evaluate(engine: Engine): Result {
  const timings: number[] = [];
  const misses: Miss[] = [];
  const falsePositives: Miss[] = [];
  const byTechnique: Record<string, { hit: number; total: number }> = {};

  const record = (c: Case, correct: boolean) => {
    byTechnique[c.technique] ??= { hit: 0, total: 0 };
    byTechnique[c.technique].total++;
    if (correct) byTechnique[c.technique].hit++;
  };

  for (const c of CORPUS) {
    const t0 = process.hrtime.bigint();
    let verdict: "block" | "allow";
    try {
      verdict = engine.run(c.cmd);
    } catch {
      // A crash is a failure, not an exemption.
      verdict = c.expected === "block" ? "allow" : "block";
    }
    timings.push(Number(process.hrtime.bigint() - t0) / 1000); // µs

    const correct = verdict === c.expected;
    record(c, correct);
    if (!correct) {
      const m: Miss = { id: c.id, technique: c.technique, cmd: c.cmd, note: c.note };
      (c.expected === "block" ? misses : falsePositives).push(m);
    }
  }

  const attacksBlocked = ATTACKS.length - misses.length;
  const benignAllowed = BENIGN.length - falsePositives.length;
  const blockRate = attacksBlocked / ATTACKS.length;
  const passRate = benignAllowed / BENIGN.length;

  timings.sort((a, b) => a - b);
  const at = (q: number) => timings[Math.min(timings.length - 1, Math.floor(timings.length * q))];

  return {
    engine: engine.name,
    approach: engine.approach,
    attacksBlocked,
    attacksTotal: ATTACKS.length,
    benignAllowed,
    benignTotal: BENIGN.length,
    blockRate,
    passRate,
    balanced: (blockRate + passRate) / 2,
    medianUs: at(0.5),
    p95Us: at(0.95),
    misses,
    falsePositives,
    byTechnique,
  };
}

// --------------------------------------------------------------------------

const showFailures = process.argv.includes("--fail");
const writeJson = process.argv.includes("--json");

const results = ENGINES.map(evaluate);

console.log(`\n\x1b[1megresso adversarial benchmark\x1b[0m`);
console.log(`${CORPUS.length} cases — ${ATTACKS.length} attacks, ${BENIGN.length} benign\n`);

console.log(
  `  ${pad("engine", 18)}${padL("attacks", 9)}${padL("benign", 9)}${padL("balanced", 10)}${padL("median", 9)}`
);
console.log(`  ${"-".repeat(18 + 9 + 9 + 10 + 9)}`);
for (const r of results) {
  const flag = r.engine === "block-everything" ? "\x1b[2m" : "";
  console.log(
    `  ${flag}${pad(r.engine, 18)}` +
      `${padL(pct(r.blockRate), 9)}` +
      `${padL(pct(r.passRate), 9)}` +
      `${padL(pct(r.balanced), 10)}` +
      `${padL(`${r.medianUs.toFixed(0)}µs`, 9)}\x1b[0m`
  );
}

// Per-technique comparison: this is where the real story is.
const techniques = [...new Set(CORPUS.map((c) => c.technique))];
const real = results.filter((r) => r.engine !== "block-everything");

console.log(`\n\x1b[1mBy technique\x1b[0m  (correct / total)\n`);
console.log(`  ${pad("technique", 20)}${real.map((r) => padL(r.engine, 18)).join("")}`);
console.log(`  ${"-".repeat(20 + real.length * 18)}`);
for (const t of techniques) {
  const cells = real.map((r) => {
    const s = r.byTechnique[t];
    const txt = `${s.hit}/${s.total}`;
    const perfect = s.hit === s.total;
    return padL(perfect ? txt : `\x1b[33m${txt}\x1b[0m`, perfect ? 18 : 27);
  });
  console.log(`  ${pad(t, 20)}${cells.join("")}`);
}

// Where egresso is actually better or worse than the baseline.
const e = results.find((r) => r.engine === "egresso")!;
const b = results.find((r) => r.engine === "regex-baseline")!;
const bMissIds = new Set(b.misses.map((m) => m.id));
const eMissIds = new Set(e.misses.map((m) => m.id));
const onlyBaselineMisses = [...bMissIds].filter((id) => !eMissIds.has(id));
const onlyEgressoMisses = [...eMissIds].filter((id) => !bMissIds.has(id));

console.log(`\n\x1b[1mHead-to-head vs regex-baseline\x1b[0m\n`);
console.log(`  attacks egresso catches that regex misses:  \x1b[32m${onlyBaselineMisses.length}\x1b[0m`);
console.log(`  attacks regex catches that egresso misses:  \x1b[31m${onlyEgressoMisses.length}\x1b[0m`);
console.log(`  false positives  egresso ${e.falsePositives.length}  |  regex ${b.falsePositives.length}`);

if (onlyBaselineMisses.length) {
  console.log(`\n  \x1b[32mCaught only by dataflow:\x1b[0m`);
  for (const id of onlyBaselineMisses.slice(0, 12)) {
    const c = CORPUS.find((x) => x.id === id)!;
    console.log(`    ${pad(id, 8)} ${pad(c.technique, 14)} ${c.cmd.slice(0, 66)}`);
  }
}

if (showFailures) {
  for (const r of real) {
    if (!r.misses.length && !r.falsePositives.length) continue;
    console.log(`\n\x1b[1m${r.engine} failures\x1b[0m`);
    for (const m of r.misses) console.log(`  \x1b[31mMISS\x1b[0m ${pad(m.id, 8)} ${m.cmd.slice(0, 74)}`);
    for (const m of r.falsePositives) console.log(`  \x1b[33mFP  \x1b[0m ${pad(m.id, 8)} ${m.cmd.slice(0, 74)}`);
  }
}

const verdictLine =
  onlyBaselineMisses.length > onlyEgressoMisses.length && e.balanced > b.balanced
    ? `\x1b[32mdataflow is buying ${onlyBaselineMisses.length - onlyEgressoMisses.length} net catches over pattern matching\x1b[0m`
    : `\x1b[31mdataflow is NOT clearly beating pattern matching — the thesis needs work or rethinking\x1b[0m`;
console.log(`\n  ${verdictLine}\n`);

if (writeJson) {
  const out = join(import.meta.dirname, "results.json");
  writeFileSync(
    out,
    JSON.stringify(
      { generatedAt: new Date().toISOString(), cases: CORPUS.length, attacks: ATTACKS.length, benign: BENIGN.length, results },
      null,
      2
    )
  );
  console.log(`  wrote ${out}\n`);
}

process.exit(0);
