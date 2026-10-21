#!/usr/bin/env node
/**
 * Clean suite -- drives lib/clean.mjs, the one module in this project that leaves FEWER files than
 * it found.
 *
 * Why this suite exists, and what it is really asserting
 * ------------------------------------------------------
 *   1. THE TABLE IS THE WHOLE PERMISSION SYSTEM. Every assertion about "this file may be removed"
 *      resolves through REMOVABLE, so the suite checks the table itself: every key names a real
 *      check, every value is a cost a reader could act on, and the three credential files are
 *      absent. A deletion feature whose exclusions are tested is a different thing from one whose
 *      exclusions are described in a comment.
 *
 *   2. REFUSAL IS THE DEFAULT AND IS ASSERTED FROM BOTH SIDES. A plan removes nothing; apply on a
 *      file whose size changed refuses it; apply on a file already gone reports that rather than
 *      failing. Each of those has a positive twin, because a check that only ever sees the refusing
 *      path passes just as well when it is refusing everything.
 *
 *   3. THE FILESYSTEM IS INJECTED, so every branch is reachable without a real file to destroy --
 *      except one end-to-end case, which does destroy a real file it just created, because the
 *      thing being advertised is that the file stops existing.
 *
 * Division of labour: checks.mjs owns the catalog, selftest owns the tool surface, matrix owns the
 *   output contract. This suite owns the removal target: its table, its plan, its refusals, and the
 *   one thing it actually does to the disk.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const clean = await import(pathToFileURL(path.join(root, "lib", "clean.mjs")).href);
const { planClean, applyClean, CLEAN_SCHEMA } = clean;
const checks = await import(pathToFileURL(path.join(root, "lib", "checks.mjs")).href);
const { REMOVABLE, CHECK_CATALOG, OPERATIONS, OPERATION_ORDER } = checks;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== the table */

section("REMOVABLE is the permission system, and it is closed");

const catalogIds = new Set(CHECK_CATALOG.map((c) => c.id));
const keys = Object.keys(REMOVABLE);

check("the schema is declared", CLEAN_SCHEMA === "aikawamei-clean/1", CLEAN_SCHEMA);
check("the table is non-empty", keys.length > 0, String(keys.length));
check("every key names a check that exists in the catalog",
  keys.every((k) => catalogIds.has(k)),
  JSON.stringify(keys.filter((k) => !catalogIds.has(k))));
check("every value is a cost, not a placeholder",
  keys.every((k) => typeof REMOVABLE[k] === "string" && REMOVABLE[k].length > 40),
  JSON.stringify(keys.filter((k) => !(typeof REMOVABLE[k] === "string" && REMOVABLE[k].length > 40))));
check("every value says what is lost rather than what the tool does",
  keys.every((k) => /lost|lost\.|discard|refetch|cost|reset|signed out|asked again|gone/i.test(REMOVABLE[k])),
  JSON.stringify(keys.filter((k) => !/lost|lost\.|discard|refetch|cost|reset|signed out|asked again|gone/i.test(REMOVABLE[k]))));

// The exclusions are the point of the table, so they are asserted by name rather than by a count.
const CREDENTIAL_IDS = ["ff-logins", "ff-keys", "ff-certs"];
check("saved logins are not removable",
  CREDENTIAL_IDS.every((id) => !(id in REMOVABLE)), JSON.stringify(CREDENTIAL_IDS.filter((id) => id in REMOVABLE)));
check("every credential check still exists in the catalog, so the exclusion is about a real file",
  CREDENTIAL_IDS.every((id) => catalogIds.has(id)),
  JSON.stringify(CREDENTIAL_IDS.filter((id) => !catalogIds.has(id))));
check("the Tor state file is removable, with its guard cost stated",
  typeof REMOVABLE["state-file"] === "string" && /guard/i.test(REMOVABLE["state-file"]),
  String(REMOVABLE["state-file"]));

section("the operation class is its own, because the writes clause promises the opposite");

check("removes is a declared operation", Object.prototype.hasOwnProperty.call(OPERATIONS, "removes"));
check("removes comes before lookup in the notice order",
  OPERATION_ORDER.indexOf("removes") >= 0 && OPERATION_ORDER.indexOf("removes") < OPERATION_ORDER.indexOf("lookup"),
  String(OPERATION_ORDER.indexOf("removes")));
check("the writes clause still promises not to modify what it reads",
  /never modifies or moves what it reads/.test(OPERATIONS.writes.clause), OPERATIONS.writes.clause);
check("the removes clause says it removes only what was reported",
  /reported/.test(OPERATIONS.removes.clause) && /never anything else/.test(OPERATIONS.removes.clause),
  OPERATIONS.removes.clause);

/* ================================================== planning */

section("a plan removes nothing, and says what it would do");

const find = (id, abs, size = 100, extra = {}) => ({
  id, layer: "metadata", severity: "warn", evidence: { size, abs, ...extra },
});

const findings = [
  find("state-file", "/t/data/state", 15004),
  find("cache-cached-descriptors", "/t/data/cached-descriptors", 4696),
  find("places", "/t/profile/places.sqlite", 5242880),
  find("ff-logins", "/t/profile/logins.json", 4096),           // in the catalog, not in the table
  find("ff-keys", "/t/profile/key4.db", 294912),
  { id: "disk-location", layer: "endpoint", severity: "ok", evidence: {} },   // no path at all
  { id: "state-guards", layer: "metadata", severity: "warn", evidence: { guards: 22, sets: ["default"] } },
];

const plan = planClean(findings);
check("the removable ones are planned", plan.planned.length === 3, String(plan.planned.length));
check("the credential files are kept, by name",
  ["ff-logins", "ff-keys"].every((id) => plan.kept.some((k) => k.id === id)),
  JSON.stringify(plan.kept.map((k) => k.id)));
check("findings with no path are in neither list",
  !plan.planned.some((p) => p.id === "disk-location") && !plan.kept.some((k) => k.id === "disk-location"));
check("every planned entry carries its path", plan.planned.every((p) => typeof p.path === "string" && p.path.length > 0));
check("every planned entry carries its cost",
  plan.planned.every((p) => typeof p.cost === "string" && p.cost.length > 40));
check("the byte total is the sum of what it would free",
  plan.total_bytes === 15004 + 4696 + 5242880, String(plan.total_bytes));

const dup = planClean([find("places", "/x/places.sqlite", 10), find("state-file", "/x/places.sqlite", 10)]);
check("one path is planned once, even when two checks name it",
  dup.planned.length === 1, JSON.stringify(dup.planned.map((p) => p.id)));

const noPath = planClean([{ id: "state-file", evidence: { size: 1 } }, { id: "state-file" }, null, "x"]);
check("malformed findings are skipped without throwing",
  noPath.planned.length === 0 && noPath.kept.length === 0);

check("an empty finding list plans nothing", planClean([]).planned.length === 0 && planClean([]).kept.length === 0);
check("planClean tolerates a missing argument", planClean().planned.length === 0);

/* ================================================== carrying it out */

section("apply re-checks each file, and refuses what no longer matches the plan");

function fakeIo(table) {
  const unlinked = [];
  return {
    unlinked,
    statOf: (p) => (table[p] ? { size: table[p], mtime: new Date() } : null),
    unlink: (p) => {
      if (p === "/boom") throw new Error("EPERM: operation not permitted");
      unlinked.push(p);
      delete table[p];
    },
  };
}

const t1 = { "/a": 100, "/b": 200 };
const io1 = fakeIo(t1);
const r1 = applyClean(planClean([find("places", "/a", 100), find("cache-cached-descriptors", "/b", 200)]), io1);
check("both files are removed", r1.removed.length === 2, JSON.stringify(r1.removed));
check("the freed byte count adds up", r1.freed_bytes === 300, String(r1.freed_bytes));
check("the io really saw both paths", io1.unlinked.length === 2, JSON.stringify(io1.unlinked));
check("nothing is refused when the sizes match", r1.refused.length === 0, JSON.stringify(r1.refused));

const t2 = { "/a": 999 };
const r2 = applyClean(planClean([find("places", "/a", 100)]), fakeIo(t2));
check("a size that changed since the audit is refused", r2.refused.length === 1, JSON.stringify(r2.refused));
check("the refusal says why, in terms of the two sizes",
  /100/.test(r2.refused[0]?.why ?? "") && /999/.test(r2.refused[0]?.why ?? ""), r2.refused[0]?.why);
check("a refused file is not removed", r2.removed.length === 0 && t2["/a"] === 999);

const r3 = applyClean(planClean([find("places", "/missing", 10)]), fakeIo({}));
check("a file that is already gone is reported, not treated as an error",
  r3.gone.length === 1 && r3.removed.length === 0 && r3.refused.length === 0, JSON.stringify(r3));

const r4 = applyClean(planClean([find("places", "/boom", 10)]), fakeIo({ "/boom": 10 }));
check("a refused unlink is reported with its reason",
  r4.refused.length === 1 && /EPERM/.test(r4.refused[0].why), JSON.stringify(r4.refused));

let threw = null;
try { applyClean({ planned: [] }, {}); } catch (e) { threw = e; }
check("apply without a filesystem refuses to pretend it worked", threw instanceof TypeError, String(threw));
let threw2 = null;
try { applyClean({ planned: [] }); } catch (e) { threw2 = e; }
check("apply without io refuses at all", threw2 instanceof TypeError, String(threw2));

/* ================================================== one real removal */

section("end to end: a file this suite created stops existing");

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-clean-"));
const victim = path.join(base, "state");
fs.writeFileSync(victim, "Guard in=default rsa_id=abc\n");
const before = fs.statSync(victim).size;

const realPlan = planClean([find("state-file", victim, before)]);
check("the plan names the file it will remove", realPlan.planned[0]?.path === victim, realPlan.planned[0]?.path);
check("a plan by itself removes nothing", fs.existsSync(victim));

const realResult = applyClean(realPlan, { statOf: (p) => { try { return { size: fs.statSync(p).size, mtime: fs.statSync(p).mtime }; } catch { return null; } }, unlink: (p) => fs.unlinkSync(p) });
check("apply removes exactly that file", realResult.removed.length === 1 && !fs.existsSync(victim), JSON.stringify(realResult.removed));
check("the reported byte count matches what the file was", realResult.freed_bytes === before, `${realResult.freed_bytes} vs ${before}`);

fs.rmSync(base, { recursive: true, force: true });

/* ================================================== summary */

console.log(`\n${fail ? "\u001b[31m" : "\u001b[32m"}${pass} passed, ${fail} failed\u001b[0m`);
if (fail) { for (const f of failures) console.log(`  - ${f}`); process.exit(1); }
