#!/usr/bin/env node
/**
 * Tool-registry suite -- the layer between a caller and a module.
 *
 * Why this exists
 * ---------------
 * The content and attribution modules were tested thoroughly at the MODULE layer: their parsers, their
 * bounds, their refusals, all asserted directly. What nothing called was the tool body in core.mjs --
 * the part that validates arguments, builds the response, attaches the catalog conformance block and
 * the fact slots. The coverage guard is what made that visible, after the release had been tagged: the
 * module was 97% covered and the tool that exposes it had never run.
 *
 * That is a real gap rather than a number, because the tool body is where a caller's mistake becomes a
 * message. A wrong argument shape, a missing required field, a filter that selects nothing -- those are
 * answered there and nowhere else.
 *
 * What it does NOT do: it never calls a tool that writes. The four that do (sessions, triage, collect,
 * self) are exercised by their own suites with fixtures and an injected io; calling them here with no
 * destination would be a test that writes to whatever directory it happens to run in.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const core = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const { TOOLS, VERSION } = core;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

const tool = (n) => TOOLS.find((t) => t.name === n);

/* ================================================== a missing argument is an answer */

section("every tool answers a missing argument instead of throwing");

// The writing tools are left out on purpose: with no destination they would either refuse (fine) or
// write (not fine), and this suite has no business guessing which.
const READ_ONLY = ["aikawamei_env", "aikawamei_version", "aikawamei_checks", "aikawamei_handoff",
  "aikawamei_content", "aikawamei_attribution"];
const threw = [];
const silent = [];
for (const name of READ_ONLY) {
  const t = tool(name);
  if (!t) { threw.push(`${name} is not registered`); continue; }
  let res = null;
  try { res = await t.execute({}); } catch (e) { threw.push(`${name}: ${e && e.message}`); continue; }
  if (!res || typeof res !== "object" || !res.schema) silent.push(name);
}
check("none of them throws on an empty argument object", threw.length === 0, threw.join("; "));
check("and each still returns a versioned response with a boundary", silent.length === 0, silent.join(","));

/* ================================================== content, through the registry */

section("aikawamei_content: arguments, filters, and the blocks a caller reads");

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-tools-"));
const F = (...p) => path.join(base, ...p);
fs.mkdirSync(F("plain"), { recursive: true });
fs.writeFileSync(F("plain/notes.txt"), "an ordinary note\n");
fs.writeFileSync(F("plain/key.txt"), "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real one\n");
const content = tool("aikawamei_content");

const noPaths = await content.execute({});
check("with no paths it refuses and says there is no default root",
  typeof noPaths.error === "string" && /has no default root/.test(noPaths.error),
  JSON.stringify(noPaths.error));
check("the refusal still carries the schema, the rules version and the boundary",
  noPaths.schema === "aikawamei-content/1" && noPaths.rules_version && Array.isArray(noPaths.boundary_notice),
  JSON.stringify({ s: noPaths.schema, r: noPaths.rules_version }));

const scanned = await content.execute({ paths: [F("plain")] });
check("a normal scan reports what it read and what it found",
  scanned.scanned_files === 2 && scanned.findings.length >= 1, JSON.stringify({ n: scanned.scanned_files, f: scanned.findings.length }));
check("the limits are echoed, so a reader knows what was and was not read",
  scanned.limits.max_bytes === 1048576 && scanned.limits.hard_max_bytes === 8388608,
  JSON.stringify(scanned.limits));
check("the rule provenance is reported rather than implied",
  scanned.rules_loaded.builtin >= 5 && scanned.rules_loaded.matchers.length === 3 && scanned.rules_loaded.clamav === 0,
  JSON.stringify(scanned.rules_loaded));
check("the catalog blocks are attached: facts, and the conformance check",
  scanned.facts && typeof scanned.facts === "object" && scanned.checks && scanned.checks.conformant === true,
  JSON.stringify({ facts: Object.keys(scanned.facts ?? {}), conformant: scanned.checks?.conformant }));
check("the three outcome lists are always present, even when empty",
  Array.isArray(scanned.not_evaluated) && Array.isArray(scanned.unreadable) && Array.isArray(scanned.skipped));

const capped = await content.execute({ paths: [F("plain")], max_bytes: 8 });
check("a ceiling below the match is reported as not evaluated, not as clean",
  capped.truncated_files === 2 && capped.findings.length === 0, JSON.stringify({ t: capped.truncated_files }));
check("and the ceiling a caller asked for is the one echoed back", capped.limits.max_bytes === 8);

const over = await content.execute({ paths: [F("plain")], max_bytes: 1e12 });
check("a ceiling above the hard maximum is clamped rather than honoured",
  over.limits.max_bytes === 8388608, String(over.limits.max_bytes));

const filtered = await content.execute({ paths: [F("plain")], min_severity: "critical" });
check("min_severity filters the findings without hiding the scan",
  filtered.findings.every((f) => f.severity === "critical") && filtered.scanned_files === 2,
  JSON.stringify({ f: filtered.findings.length, s: filtered.scanned_files }));

const layered = await content.execute({ paths: [F("plain")], layer: "transport" });
check("a layer with no findings returns none rather than everything",
  layered.findings.length === 0, String(layered.findings.length));

const withDb = await content.execute({ paths: [F("plain")], clamav_dir: F("nope") });
check("a signature directory that does not exist is reported in the response",
  withDb.rules_loaded.clamav_problems.length === 1 && withDb.rules_loaded.clamav === 0,
  JSON.stringify(withDb.rules_loaded.clamav_problems));

const badFiles = await content.execute({ paths: [F("does-not-exist")] });
check("a path that does not exist lands in skipped, and the scan says it read nothing",
  badFiles.skipped.length === 1 && badFiles.scanned_files === 0, JSON.stringify(badFiles.skipped));

/* ================================================== attribution, through the registry */

section("aikawamei_attribution: the switch, the outline, and what it will not say");

const attribution = tool("aikawamei_attribution");
const noTargets = await attribution.execute({});
check("with no targets it refuses, and says why it has nothing to say",
  typeof noTargets.error === "string" && /nothing to say about an unnamed adversary/.test(noTargets.error),
  JSON.stringify(noTargets.error));
check("and it declares the lookup operation even while refusing, because the tool can dial",
  noTargets.operations.includes("lookup"), JSON.stringify(noTargets.operations));

const offline = await attribution.execute({ targets: ["example.com", "AS15169", "abuse@example.org"] });
check("by default it looks nothing up", offline.lookups.length === 0 && offline.lookup_allowed === false);
check("and it says where the transport comes from, which is the tool layer rather than the module",
  offline.lookup_transport === "provided by the caller",
  String(offline.lookup_transport));
check("each target gets a route and a command for a person to run",
  offline.routes.length === 3 && offline.commands.length === 3
  && offline.commands[0].commands.some((c) => c.shell === "bash") && offline.commands[0].commands.some((c) => c.shell === "pwsh"),
  JSON.stringify(offline.commands[0].commands.map((c) => c.shell)));
check("a target of unknown shape is reported with no command, rather than a wrong one",
  (await attribution.execute({ targets: ["!!"] })).commands[0].commands.length === 0);
check("the evidence grades and the not-claimable list travel with every answer",
  offline.evidence_grades.length === 5 && offline.not_claimable.length === 5);
check("the report outline is built for the level asked for",
  (await attribution.execute({ targets: ["example.com"], tlp: "TLP:CLEAR" })).report.tlp === "TLP:CLEAR");
check("an unknown level falls back rather than travelling unmarked",
  (await attribution.execute({ targets: ["example.com"], tlp: "TLP:PURPLE" })).report.tlp === "TLP:AMBER");
check("the facts and conformance blocks are attached here too",
  offline.facts && offline.checks && offline.checks.conformant === true, JSON.stringify(offline.checks?.unknown));

/* ================================================== clean, through the registry */

section("aikawamei_clean: a plan, and the operation class it declares");

// Called with apply absent, which is the default -- so this cannot delete anything, whichever shape
// it answers with. Both shapes are accepted on purpose: on this machine the audit finds a Tor
// install and produces a plan, on a runner with neither target it produces the empty answer, and a
// test that needs Tor to exist is a test that only passes where it was written.
const cleanTool = tool("aikawamei_clean");
const plan = await cleanTool.execute({});
check("clean answers with its schema whether or not it found a target",
  plan.schema === "aikawamei-clean/1", String(plan.schema));
check("clean declares the removal class, and does not claim the writes clause it would contradict",
  plan.operations.includes("removes") && !plan.operations.includes("writes"), JSON.stringify(plan.operations));
check("the default is a plan: nothing is removed",
  Array.isArray(plan.removed) && plan.removed.length === 0, JSON.stringify(plan.removed));
check("both lists are always present, so a caller never branches on which keys exist",
  Array.isArray(plan.planned) && Array.isArray(plan.kept), JSON.stringify(Object.keys(plan)));
check("the removal notice travels with every answer, including the empty one",
  Array.isArray(plan.removal_notice) && plan.removal_notice.length >= 3, String(plan.removal_notice?.length));
check("a mode is always stated", typeof plan.mode === "string", String(plan.mode));

// apply true with an id that cannot match anything: the applied branch runs and removes nothing.
const noop = await cleanTool.execute({ apply: true, only: ["a-check-id-that-does-not-exist"] });
check("apply with nothing eligible removes nothing and reports it",
  (noop.removed ?? []).length === 0 && noop.freed_bytes === 0,
  JSON.stringify({ mode: noop.mode, removed: noop.removed, freed: noop.freed_bytes }));
check("and it still carries the notice, because 'nothing was removed' is also a claim",
  Array.isArray(noop.removal_notice) && noop.removal_notice.length >= 3);

/* ================================================== neutralize, through the registry */

section("aikawamei_neutralize: the order, and the refusal to act");

// Both scans switched off, so this reads nothing and queries nothing. What is asserted is the
// SHAPE, because the shape is the contract: four layers always present, an order always explained,
// and a tool that declares neither a write nor a removal.
const neut = tool("aikawamei_neutralize");
const emptyPlan = await neut.execute({ scan_credentials: false, scan_persistence: false });
check("neutralize answers with its schema", emptyPlan.schema === "aikawamei-neutralize/1", String(emptyPlan.schema));
check("it declares neither a write nor a removal",
  !emptyPlan.operations.includes("writes") && !emptyPlan.operations.includes("removes"), JSON.stringify(emptyPlan.operations));
check("all four layers are present as lists, even when empty",
  ["sever", "disable", "purge", "revoke"].every((l) => Array.isArray(emptyPlan.steps?.[l])),
  JSON.stringify(Object.keys(emptyPlan.steps ?? {})));
check("it names the layers it could not fill", emptyPlan.empty_layers.length === 4, JSON.stringify(emptyPlan.empty_layers));
check("the order is still explained when nothing was found",
  typeof emptyPlan.why_this_order === "string" && emptyPlan.why_this_order.length > 40, String(emptyPlan.why_this_order));
check("and it says that nothing was carried out",
  Array.isArray(emptyPlan.not_claimed) && emptyPlan.not_claimed.some((s) => /executes nothing/.test(s)),
  JSON.stringify(emptyPlan.not_claimed?.length));
check("a count is reported for every layer", typeof emptyPlan.counts?.by_layer?.sever === "number",
  JSON.stringify(emptyPlan.counts));

/* ================================================== terminate, through the registry */

section("aikawamei_terminate: it plans by default, and does not claim the shared closing line");

const term = tool("aikawamei_terminate");
const termPlan = await term.execute({});
check("terminate answers with its schema", termPlan.schema === "aikawamei-terminate/1", String(termPlan.schema));
check("it declares the termination class and not the removal one",
  termPlan.operations.includes("terminates") && !termPlan.operations.includes("removes"), JSON.stringify(termPlan.operations));
check("the default is a plan: nothing was ended",
  termPlan.mode === "planned" && Array.isArray(termPlan.ended) && termPlan.ended.length === 0, JSON.stringify(termPlan.mode));
check("with nothing named it matches nothing, and says so twice over",
  termPlan.matched.length === 0 && termPlan.unmatched.length === 0,
  JSON.stringify({ m: termPlan.matched.length, u: termPlan.unmatched.length }));
check("it says a kill is not a neutralisation",
  termPlan.not_claimed.some((s) => /kill removes the activity/.test(s)));
// The shared closing line says the tool protects what is visible "without running anything". This is
// the one tool that ends processes, so its notice has to carry that exception rather than inherit a
// sentence that is no longer true of it.
check("its boundary notice states the exception rather than inheriting a false line",
  termPlan.boundary_notice.some((l) => /also changes the running state/.test(l)), JSON.stringify(termPlan.boundary_notice));
check("and it keeps the misuse warning every tool carries",
  termPlan.boundary_notice.some((l) => /A clean audit is NOT proof of safety/.test(l)));
// "Nothing matched" means two different things depending on whether the process table could be read
// at all. The CI run that added this tool failed on a Linux runner with `powershell.exe: not found`,
// which is a crash rather than a boundary, so the instrument is named in the response.
check("it says which instrument answered",
  ["windows-cim", "unsupported"].includes(termPlan.enumerator), String(termPlan.enumerator));

/* ================================================== cleanup */

try { fs.rmSync(base, { recursive: true, force: true }); } catch { /* a fixture that will not delete is not a failure */ }

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
