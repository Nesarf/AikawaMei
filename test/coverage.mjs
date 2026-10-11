#!/usr/bin/env node
/**
 * Line-coverage collection -- the "evidence" that the suites actually traverse the code.
 *
 * How it works: NODE_V8_COVERAGE makes V8 dump its own coverage data. We run every suite
 * (net / matrix / mcp-smoke / firefox / selftest), then aggregate per line and report the lines
 * that were NEVER executed.
 *
 * Unexecuted lines are paths the suites never reached -- that is more informative than
 * "all tests green": green only says what ran was right, coverage tells you where nothing
 * ran at all.
 *
 * Usage:
 *   node test/coverage.mjs              report uncovered lines
 *   node test/coverage.mjs --min 85     exit code 1 if coverage is below the threshold
 *   node test/coverage.mjs --gap        print only the uncovered line numbers, for reading
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const argv = process.argv.slice(2);
const wantGap = argv.includes("--gap");
const minIdx = argv.indexOf("--min");
const minPct = minIdx >= 0 ? Number(argv[minIdx + 1]) : null;

const covDir = fs.mkdtempSync(path.join(os.tmpdir(), "tpa-cov-"));
// Order matters only for cost: net / matrix / mcp-smoke / firefox / emblem are fast (firefox and
// emblem work from synthetic fixtures and finish in well under a second), selftest is the heaviest
// suite, so it runs last.
const suites = ["test/net.mjs", "test/matrix.mjs", "test/mcp-smoke.mjs", "test/firefox.mjs", "test/emblem.mjs", "test/checks.mjs", "test/sessions.mjs", "test/scope.mjs", "test/vault.mjs", "test/triage.mjs", "test/collect.mjs", "test/selfcheck.mjs", "test/baseline.mjs", "test/selftest.mjs"];

console.log("== running the suites (V8 coverage enabled) ==");
const results = [];
for (const s of suites) {
  const r = spawnSync(process.execPath, [path.join(root, s)], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, NODE_V8_COVERAGE: covDir, NO_COLOR: "1" },
  });
  const ok = r.status === 0;
  // The suite's own count, kept so the README's verification table can be checked against it below.
  // A count in prose that nothing compares against the output is a number that drifts, and this
  // project has already recorded that defect once: the table said "800 items" for two rounds after
  // the suite had passed 845.
  const counted = /passed (\d+) \/ (\d+)/.exec(String(r.stdout ?? ""));
  results.push({ suite: s, ok, status: r.status, items: counted ? Number(counted[1]) : null });
  console.log(`  ${ok ? "\u001b[32m[ok]\u001b[0m" : "\u001b[31m[FAIL]\u001b[0m"} ${s}  exit=${r.status}`);
}

/* ----------- parse the V8 coverage ----------- */

const files = fs.readdirSync(covDir).filter((f) => f.endsWith(".json"));
console.log(`\n== coverage data: ${files.length} file(s) ==`);

/** per script url -> Set(executed line numbers) */
const perScript = new Map();

function lineStartsOf(src) {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

for (const f of files) {
  let data;
  try { data = JSON.parse(fs.readFileSync(path.join(covDir, f), "utf8")); } catch { continue; }
  for (const script of data.result ?? []) {
    const url = script.url ?? "";
    if (!url.startsWith("file://")) continue;
    // Only this repo's lib/ matters (skip node_modules and the tests themselves)
    let p;
    try { p = fileURLToPath(url); } catch { continue; }
    if (!p.startsWith(root)) continue;
    if (p.includes("node_modules")) continue;
    if (!p.includes(`${path.sep}lib${path.sep}`)) continue;

    let src;
    try { src = fs.readFileSync(p, "utf8"); } catch { continue; }
    const starts = lineStartsOf(src);

    // Merge the multiple ranges of the same script (take the max count for overlapping spans)
    const byKey = new Map();
    for (const fn of script.functions ?? []) {
      for (const r of fn.ranges ?? []) {
        const k = `${r.startOffset}:${r.endOffset}`;
        const cur = byKey.get(k);
        if (cur === undefined || r.count > cur) byKey.set(k, r.count);
      }
    }
    const ranges = [...byKey.entries()].map(([k, count]) => {
      const [s, e] = k.split(":").map(Number);
      return { startOffset: s, endOffset: e, count };
    });

    const covered = perScript.get(p) ?? new Set();
    for (let ln = 0; ln < starts.length; ln++) {
      const off = starts[ln];
      let best = null;
      for (const r of ranges) {
        if (off >= r.startOffset && off < r.endOffset) {
          if (!best || r.endOffset - r.startOffset < best.endOffset - best.startOffset) best = r;
        }
      }
      if (best && best.count > 0) covered.add(ln + 1);
    }
    perScript.set(p, covered);
  }
}

/* ----------- report ----------- */

function compress(nums) {
  const out = [];
  const sorted = [...nums].sort((a, b) => a - b);
  let i = 0;
  while (i < sorted.length) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1] === sorted[j] + 1) j++;
    out.push(i === j ? `${sorted[i]}` : `${sorted[i]}-${sorted[j]}`);
    i = j + 1;
  }
  return out;
}

console.log("\n== line coverage (lib/ production code) ==");
let totalLines = 0, totalCov = 0;
const rows = [];

for (const [p, covered] of [...perScript.entries()].sort()) {
  const src = fs.readFileSync(p, "utf8");
  const all = src.split(/\r?\n/);
  // Count only "meaningful" lines: ignore blank lines and pure comment lines, otherwise the coverage number means nothing
  const meaningful = [];
  let inBlock = false;
  for (let i = 0; i < all.length; i++) {
    const raw = all[i];
    const t = raw.trim();
    if (inBlock) { if (t.includes("*/")) inBlock = false; continue; }
    if (t.startsWith("/*")) { if (!t.includes("*/")) inBlock = true; continue; }
    if (!t || t.startsWith("//") || t.startsWith("*")) continue;
    meaningful.push(i + 1);
  }
  const hit = meaningful.filter((ln) => covered.has(ln));
  const miss = meaningful.filter((ln) => !covered.has(ln));
  const pct = meaningful.length ? (hit.length / meaningful.length) * 100 : 100;
  totalLines += meaningful.length;
  totalCov += hit.length;
  rows.push({ file: path.relative(root, p), meaningful: meaningful.length, hit: hit.length, miss, pct });
}

for (const r of rows) {
  const bar = r.pct >= 95 ? "\u001b[32m" : r.pct >= 85 ? "\u001b[33m" : "\u001b[31m";
  console.log(`  ${r.file.padEnd(18)} ${String(r.hit).padStart(4)}/${String(r.meaningful).padEnd(4)}  ${bar}${r.pct.toFixed(1)}%\u001b[0m`);
  if (!wantGap && r.miss.length) {
    console.log(`\u001b[90m      uncovered lines: ${compress(r.miss).join(", ")}\u001b[0m`);
  }
}

const overall = totalLines ? (totalCov / totalLines) * 100 : 100;
console.log(`\n  total  ${totalCov}/${totalLines}  \u001b[1m${overall.toFixed(1)}%\u001b[0m`);

if (wantGap) {
  console.log("\n== uncovered line detail ==");
  for (const r of rows) {
    if (!r.miss.length) continue;
    console.log(`\n  ${r.file}:`);
    const src = fs.readFileSync(path.join(root, r.file), "utf8").split(/\r?\n/);
    for (const ln of r.miss) console.log(`    ${String(ln).padStart(4)} | ${src[ln - 1]}`);
  }
}

try { fs.rmSync(covDir, { recursive: true, force: true }); } catch {}

/* =====================================================================
 * The README's verification table against the numbers in this run
 *
 * A count written in prose that nothing compares against the output is a number that drifts, and
 * this project has recorded that defect once already: the table said "800 items" for two rounds
 * after the suite had been passing 845. The comparison lives HERE rather than in a suite because
 * this is the one place that runs every suite and can see all their counts at once.
 */
// BOTH documents, because the guard used to protect one of them and the other drifted silently:
// this file's own history records a count left in prose for two rounds after the suite had moved.
const DOCS = ["README.md", "PROOFREADING.md"];
const claimed = new Map();
let covCell = null;
for (const doc of DOCS) {
  const text = fs.readFileSync(path.join(root, doc), "utf8");
  for (const m of text.matchAll(/\| `(test\/[a-z-]+\.mjs)` \|.*?\| \*\*([\d,]+) items\*\* \|/g)) {
    claimed.set(`${doc}:${m[1]}`, Number(m[2].replace(/,/g, "")));
  }
  // ONE FIGURE PER PLATFORM, because the number genuinely differs: a tool that reads Windows-only
  // artefacts covers fewer lines on Linux, and the docs recorded a single figure that could only ever
  // match one of the two -- which is exactly how the first CI run on a Linux runner failed.
  const cell = /\*\*(\d+)\/(\d+) = ([\d.]+)%\*\* on Windows, \*\*(\d+)\/(\d+) = ([\d.]+)%\*\* on Linux/.exec(text);
  if (cell && !covCell) {
    covCell = process.platform === "win32"
      ? [cell[0], cell[1], cell[2], cell[3]]
      : [cell[0], cell[4], cell[5], cell[6]];
  }
}
const drift = [];
for (const r of results) {
  if (r.items === null) continue; // a suite that reports calls rather than items has no cell
  for (const doc of DOCS) {
    const want = claimed.get(`${doc}:${r.suite}`);
    if (want === undefined) { drift.push(`${doc}: no row for ${r.suite}`); continue; }
    if (want !== r.items) drift.push(`${doc}: says ${want} items for ${r.suite}, the suite passed ${r.items}`);
  }
}
if (!covCell) drift.push("the coverage row has no figure");
else if (claimed.size === 0) drift.push("no suite counts were parsed out of either document");
else {
  // THE ITEM COUNTS ABOVE ARE EXACT; THE COVERAGE FRACTION IS NOT, and pretending otherwise would be
  // a claim this repository cannot back. Which lines are instrumented, and therefore how many there
  // are, moves with the Node build: the same tree measures 4576/4626 here and 4533/4626 on the Linux
  // side, from the same suites passing the same 14/14. So the recorded figure is checked exactly on
  // the platform it was measured on, and within a percentage point elsewhere -- with the measured
  // value printed either way, because a number a reader cannot see is a number they cannot check.
  const saysRatio = Number(covCell[3]);
  const measuredRatio = totalLines ? (totalCov / totalLines) * 100 : 0;
  const exact = covCell[1] === String(totalCov) && covCell[2] === String(totalLines);
  const close = Math.abs(measuredRatio - saysRatio) <= 1.0;
  const expected = process.platform === "win32";
  if ((expected && !exact) || (!expected && !close)) {
    drift.push(`coverage: the docs say ${covCell[1]}/${covCell[2]} = ${covCell[3]}% for ${expected ? "Windows" : "Linux"}, this run measured ${totalCov}/${totalLines} = ${measuredRatio.toFixed(1)}%`);
  } else if (!exact) {
    console.log(`  \u001b[90mcoverage on this platform: ${totalCov}/${totalLines} = ${measuredRatio.toFixed(1)}%, against ${saysRatio}% recorded for it\u001b[0m`);
  }
}
if (drift.length) {
  console.log("\n  \u001b[31mthe verification table no longer matches the suites\u001b[0m");
  for (const d of drift) console.log(`    ${d}`);
}

const suiteFailed = results.some((r) => !r.ok);
console.log(
  `\n  Summary: suites ${results.filter((r) => r.ok).length}/${results.length} passed, line coverage ${overall.toFixed(1)}%`
);

if (drift.length) process.exit(1);
if (suiteFailed) process.exit(1);
if (minPct !== null && overall < minPct) {
  console.log(`  \u001b[31mcoverage ${overall.toFixed(1)}% is below the threshold ${minPct}%\u001b[0m`);
  process.exit(1);
}
process.exit(0);
