#!/usr/bin/env node
/**
 * Collection suite -- drives lib/collect.mjs, the one part of this project that writes.
 *
 * Why this needs its own suite:
 *
 *   1. It writes, so the property that matters most is the one about what it does NOT touch: the
 *      original. Every case below records the source's digest and mtime before the collection and
 *      asserts they are unchanged afterwards, because a collector that quietly normalised, truncated
 *      or re-timestamped what it collected would have destroyed the thing it was sent to preserve.
 *
 *   2. A copy kept inside the evidence is not a copy. The destination rule is asserted in both
 *      directions -- refused when it is inside a source, allowed when it is a sibling -- because a
 *      rule that only ever refuses would pass a one-sided test while making the tool unusable.
 *
 *   3. The order of volatility is a claim about what will be lost first, and it is only useful if it
 *      is stable within a class: the sort must not scramble the caller's order among equally
 *      perishable files, or a caller who listed a directory in readdir order gets a different
 *      manifest every run.
 *
 * Hermeticity: everything is built in a temp directory that is removed at the end.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const {
  COLLECT_SCHEMA, COLLECT_MAX_BYTES, COLLECT_NOT_REACHABLE,
  VOLATILITY_ORDER, collectInto, destinationInsideSources, digestOfFile, orderByVolatility, volatilityOf,
} = await import(pathToFileURL(path.join(root, "lib", "collect.mjs")).href);
const { verifyChain } = await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ====================== fixture ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-collect-"));
const F = (...p) => path.join(base, ...p);
function put(rel, data) {
  const full = F(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data);
  return full;
}

const scene = F("scene");
const werFile = put("scene/AppData/Local/Microsoft/Windows/WER/ReportQueue/R/Report.wer", "report body");
const pfFile = put("scene/Windows/Prefetch/THING.EXE-1A2B3C4D.pf", "pf body");
const taskFile = put("scene/Windows/System32/Tasks/MyTask", "<Task/>");
const exeFile = put("scene/AppData/Local/t/thing.exe", "MZ binary");
const twinA = put("scene/a/same.txt", "from a");
const twinB = put("scene/b/same.txt", "from b");
const bigFile = put("scene/big.bin", "x".repeat(4096));
const sources = [exeFile, taskFile, pfFile, werFile];

/* ====================== A. the order ====================== */

section("A. what is lost first");

check("a crash-report path is ephemeral", volatilityOf(werFile) === "ephemeral", volatilityOf(werFile));
check("so is anything under a temp directory", volatilityOf("/tmp/x/y.dat") === "ephemeral");
check("prefetch rolls over with use", volatilityOf(pfFile) === "rolling", volatilityOf(pfFile));
check("a scheduled task is durable", volatilityOf(taskFile) === "durable", volatilityOf(taskFile));
check("an executable is static", volatilityOf(exeFile) === "static", volatilityOf(exeFile));
check("a path nothing recognises is durable, which is the honest middle", volatilityOf("/somewhere/unknown.dat") === "durable");

const ordered = orderByVolatility([exeFile, taskFile, pfFile, werFile]);
check("the order runs most perishable first",
  ordered.map(volatilityOf).join(",") === "ephemeral,rolling,durable,static", ordered.map(volatilityOf).join(","));

// The stable-sort property, which is the difference between a deterministic manifest and one that
// changes every run.
const sameClass = [F("scene/z/one.pf"), F("scene/a/two.pf"), F("scene/m/three.pf")];
check("within a class the caller's order is kept",
  JSON.stringify(orderByVolatility(sameClass)) === JSON.stringify(sameClass), JSON.stringify(orderByVolatility(sameClass)));
check("an empty list is an empty order", orderByVolatility([]).length === 0 && orderByVolatility(null).length === 0);

/* ====================== B. where the copy may land ====================== */

section("B. the destination");

check("a destination inside a source is refused", destinationInsideSources(F("scene/out"), [scene]) === path.resolve(scene));
check("a destination equal to a source is refused", destinationInsideSources(scene, [scene]) === path.resolve(scene));
check("a SIBLING destination is allowed, which is the control", destinationInsideSources(F("out"), [scene]) === null);
check("a file source cannot contain a destination, so the rule is about the ROOTS a caller names",
  destinationInsideSources(F("scene/out"), [werFile]) === null, "documented rather than silently assumed");
check("a destination that merely shares a prefix is allowed",
  destinationInsideSources(F("scene-elsewhere/out"), [scene]) === null, "the prefix bug, at the guard");

const noDest = collectInto({ sources });
check("no destination is a refusal with a reason, not a throw",
  noDest.entries.length === 0 && /no destination/.test(noDest.refused[0].reason), JSON.stringify(noDest.refused));
// A source here is the ROOT being collected from, not the individual files: "inside the evidence" is
// a claim about trees, and a caller collecting from a tree names the tree.
const insideDest = collectInto({ sources: [scene], destination: F("scene/collected") });
check("collecting into the evidence is refused for the reason it is refused",
  insideDest.entries.length === 0 && /copy kept inside the evidence/.test(insideDest.refused[0].reason),
  JSON.stringify(insideDest.refused));
check("...and nothing was written there", !fs.existsSync(F("scene/collected")));

/* ====================== C. the collection ====================== */

section("C. collecting");

const destination = F("out");
const before = new Map(sources.map((s) => [s, { digest: digestOfFile(s), mtime: fs.statSync(s).mtimeMs, size: fs.statSync(s).size }]));

const result = collectInto({ sources, destination, at: "2026-03-04T05:06:07.000Z", operator: "the suite" });
check("every file was collected", result.entries.length === 4, JSON.stringify(result.refused));
check("the manifest was written", fs.existsSync(result.manifest_path));
check("the copies exist", result.entries.every((e) => fs.existsSync(e.copy)));
check("the files were taken in volatility order",
  result.entries.map((e) => e.volatility).join(",") === "ephemeral,rolling,durable,static",
  result.entries.map((e) => e.volatility).join(","));

// The property that matters most: the original is not touched.
check("no source changed while being collected",
  sources.every((s) => {
    const b = before.get(s);
    const now = fs.statSync(s);
    return digestOfFile(s) === b.digest && now.mtimeMs === b.mtime && now.size === b.size;
  }), JSON.stringify(sources.map((s) => [digestOfFile(s) === before.get(s).digest, fs.statSync(s).mtimeMs === before.get(s).mtime])));

// The copy is usable as evidence, which means its timestamps line up with everything else.
check("a copy carries the original's mtime, not the time it was made",
  result.entries.every((e) => Math.abs(fs.statSync(e.copy).mtimeMs - before.get(e.source).mtime) < 2),
  JSON.stringify(result.entries.map((e) => [fs.statSync(e.copy).mtimeMs, before.get(e.source).mtime])));
check("a copy's digest is the original's", result.entries.every((e) => e.sha256 === digestOfFile(e.source)));
check("and the entry says it verified that", result.entries.every((e) => e.verified === true));
check("the operator and the time are recorded, because they are claims a record has to carry",
  result.entries.every((e) => e.operator === "the suite" && e.collected_at === "2026-03-04T05:06:07.000Z"));

// The manifest is a chain, in the same shape the vault verifies -- so a later check can prove it was
// not edited, using the tool that already exists.
const manifestLines = fs.readFileSync(result.manifest_path, "utf8").trim().split("\n");
check("the manifest is one line per entry", manifestLines.length === 4, String(manifestLines.length));
check("the manifest is a verifiable chain, using the vault's own verifier",
  verifyChain(manifestLines).ok === true, JSON.stringify(verifyChain(manifestLines)));
const edited = manifestLines.slice();
const asObject = JSON.parse(edited[0]);
asObject.size = 1;
edited[0] = JSON.stringify(asObject);
check("an edited manifest line breaks the chain", verifyChain(edited).ok === false, JSON.stringify(verifyChain(edited).broken));
check("the head is reported so a receipt can be kept", typeof result.manifest_head === "string" && result.manifest_head.length === 64);

/* ====================== D. what it refuses ====================== */

section("D. what it will not take");

const overCeiling = collectInto({ sources: [bigFile], destination: F("out2"), maxBytes: 100 });
check("a file over the ceiling is refused and recorded, not silently skipped",
  overCeiling.entries.length === 0 && /ceiling/.test(overCeiling.refused[0].reason), JSON.stringify(overCeiling.refused));
check("...and its size is in the refusal, so a reader can see how far over it was",
  overCeiling.refused[0].size === 4096, JSON.stringify(overCeiling.refused[0]));
check("the same file under a large ceiling is collected, which is the control",
  collectInto({ sources: [bigFile], destination: F("out2b"), maxBytes: 1 << 20 }).entries.length === 1);
check("the default ceiling is stated rather than implied", COLLECT_MAX_BYTES === 64 * 1024 * 1024, String(COLLECT_MAX_BYTES));

const missing = collectInto({ sources: [F("scene/not-here")], destination: F("out3") });
check("a file that is not there is refused with a reason", /not present/.test(missing.refused[0].reason), JSON.stringify(missing.refused));
const dir = collectInto({ sources: [scene], destination: F("out4") });
check("a directory is refused as not a regular file", /not a regular file/.test(dir.refused[0].reason), JSON.stringify(dir.refused));

// Two files with the same basename: both have to survive, or the manifest's mapping is a lie.
const twins = collectInto({ sources: [twinA, twinB], destination: F("out5") });
check("two files with the same name are both collected",
  twins.entries.length === 2 && fs.readFileSync(twins.entries[0].copy, "utf8") === "from a"
  && fs.readFileSync(twins.entries[1].copy, "utf8") === "from b",
  JSON.stringify(twins.entries.map((e) => e.copy)));
check("...and the copies are distinct files", twins.entries[0].copy !== twins.entries[1].copy);
check("the ordinal ties the manifest to the copy layout",
  twins.entries.map((e) => e.ordinal).join(",") === "1,2", JSON.stringify(twins.entries.map((e) => e.ordinal)));

/* ====================== D2. the paths that go wrong ====================== */

section("D2. when a copy cannot be made");

// Reachable without any test-only door: the ordinal is assigned before the copy, so a destination
// where that name is already a DIRECTORY makes the copy fail. A real destination can be in that
// state, and the run has to record the refusal rather than stop or pretend.
const blocked = F("out6");
fs.mkdirSync(path.join(blocked, "files", "0001-Report.wer"), { recursive: true });
const blockedRun = collectInto({ sources: [werFile], destination: blocked });
check("a copy that cannot be written is refused, not thrown",
  blockedRun.entries.length === 0 && /could not be copied/.test(blockedRun.refused[0]?.reason ?? ""),
  JSON.stringify(blockedRun.refused));
check("...and the manifest is still written, so the run is recorded",
  fs.existsSync(blockedRun.manifest_path));

check("a digest of something that cannot be read is null rather than a throw",
  digestOfFile(scene) === null && digestOfFile(F("scene/not-here")) === null);
check("a digest of a real file is its sha256, so the null above is not the only answer",
  /^[0-9a-f]{64}$/.test(digestOfFile(werFile) ?? ""));

/* ====================== E. what it cannot reach ====================== */

section("E. the part of the order it cannot run");

check("the list is not empty", COLLECT_NOT_REACHABLE.length >= 4, String(COLLECT_NOT_REACHABLE.length));
check("every entry names the surface, why, and the instrument that can",
  COLLECT_NOT_REACHABLE.every((e) => e.surface && e.why && e.answerable_by));
check("memory is listed first, because it is first in the order and out of reach here",
  COLLECT_NOT_REACHABLE[0].surface === "memory" && /winpmem|DumpIt/.test(COLLECT_NOT_REACHABLE[0].answerable_by));
check("the live process table is listed too", COLLECT_NOT_REACHABLE.some((e) => /process table/.test(e.surface)));
check("the order of volatility is reported with the result",
  JSON.stringify(result.order) === JSON.stringify(VOLATILITY_ORDER), JSON.stringify(result.order));
check("the schema is versioned", /^aikawamei-collect\/\d+$/.test(COLLECT_SCHEMA), COLLECT_SCHEMA);

/* ====================== F. the tool ====================== */

section("F. the tool");

const tools = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const collectTool = tools.TOOLS.find((t) => t.name === "aikawamei_collect");

check("the tool exists and is registered", !!collectTool);
check("it declares that it writes, and that it does not reach the network",
  collectTool.operations.includes("writes") && !collectTool.operations.includes("lookup"),
  JSON.stringify(collectTool.operations));

// The vocabulary change, asserted where it matters: the notice has to name BOTH the writing and the
// network, because a ranking could only ever have named one of them.
const notice = tools.boundaryFor(collectTool.operations)[0];
// Asserted as PROPERTIES rather than as wording: the clause is shared by the three tools that
// write, and pinning it character for character here would mean every future edit to one sentence
// breaks a test in a file about something else.
check("its notice says it writes", /writes files/i.test(notice), notice);
check("...and says it does not modify what it reads", /never modifies/i.test(notice), notice);
check("...and still says it never touches the network", /never touches the network/i.test(notice), notice);
check("...and never claims to be read-only", !/performs a static audit only/i.test(notice), notice);

// Named with its section, because this file already has a `noDest` from the module's own tests and
// a duplicate identifier is a load-time failure rather than a test failure.
const toolNoDest = await collectTool.execute({ paths: [werFile] });
check("no destination is an error, not a default", typeof toolNoDest.error === "string", JSON.stringify(toolNoDest).slice(0, 120));

const toolDest = F("tool-out");
const toolRun = await collectTool.execute({ paths: sources, destination: toolDest });
check("the tool collected what it was pointed at", toolRun.collected === 4, JSON.stringify(toolRun.refused));
check("the copies and the manifest are where it said", fs.existsSync(toolRun.manifest_path) && toolRun.entries.every((e) => fs.existsSync(e.copy)));
check("the manifest is a chain the vault can verify",
  verifyChain(fs.readFileSync(toolRun.manifest_path, "utf8").trim().split("\n")).ok === true);
check("the order it used is reported", Array.isArray(toolRun.order) && toolRun.order[0] === "ephemeral", JSON.stringify(toolRun.order));
check("the surfaces a collector of this shape cannot reach travel with the answer",
  toolRun.not_reachable.length >= 4 && /winpmem|DumpIt/.test(toolRun.not_reachable[0].answerable_by));

const intoEvidence = await collectTool.execute({ paths: sources, destination: F("scene/tool-out"), sources: [scene] });
check("a destination inside the evidence is refused by the tool too",
  intoEvidence.refused_destination !== null && intoEvidence.collected === 0,
  JSON.stringify(intoEvidence.refused_destination));
check("...and nothing was written there", !fs.existsSync(F("scene/tool-out")));

const scopedOut = await collectTool.execute({ paths: sources, destination: F("tool-out2"), scope: [F("out")] });
check("a path outside a declared scope is refused rather than copied",
  scopedOut.refused_by_scope.length === 4 && scopedOut.collected === 0, JSON.stringify(scopedOut.refused_by_scope));
check("...and the refusal names the path", typeof scopedOut.refused_by_scope[0]?.reason === "string");

process.env.AIKAWAMEI_VAULT_PASSPHRASE = "a passphrase for the suite";
const collectChain = path.join(F("chain-dir"), "chain.jsonl");
const withVault = await collectTool.execute({ paths: sources, destination: F("tool-out3"), vault: collectChain });
const rawChain = fs.readFileSync(collectChain, "utf8");
check("a collection can leave a record", withVault.vault?.length === 1 && withVault.vault.sealed === true, JSON.stringify(withVault.vault));
check("the record counts what it did", /file\(s\) copied/.test(rawChain), rawChain.slice(0, 140));
check("the cleartext names no collected path",
  !rawChain.includes("Report.wer") && !rawChain.includes("THING.EXE"), rawChain.slice(0, 160));
const openedCollection = (await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href))
  .openValue(process.env.AIKAWAMEI_VAULT_PASSPHRASE, JSON.parse(rawChain.trim()).sealed);
check("...and the sealed payload holds them", JSON.stringify(openedCollection.manifest).includes("Report.wer"));
delete process.env.AIKAWAMEI_VAULT_PASSPHRASE;
check("with no vault named, nothing is written",
  (await collectTool.execute({ paths: sources, destination: F("tool-out4") })).vault === undefined);

/* ====================== summary ====================== */

try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mtemporary scene removed\u001b[0m"); } catch {}

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
