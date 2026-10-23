#!/usr/bin/env node
/**
 * Terminate suite -- drives lib/terminate.mjs, the only module here that changes the RUNNING state of
 * the machine.
 *
 * What it is really asserting
 * ---------------------------
 *   1. THE SECOND LOOK IS THE FEATURE. A kill is easy; `respawnReport` is what separates "neutralised"
 *      from "killed and back". Both outcomes are asserted, and the "it came back" case is built from
 *      a DIFFERENT pid -- because that is what a restart looks like, while the same pid in both
 *      snapshots means the kill never happened.
 *   2. NOTHING IS SWEPT. A request names a path or a name; a process that matches neither is never in
 *      the plan, and a request that matches nothing is reported rather than resolved to "closest".
 *   3. THE TERMINATING PROCESS IS REFUSED, AND THE REFUSAL IS VISIBLE. Filtering it out silently
 *      would look the same as never having matched it.
 */
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const mod = await import(pathToFileURL(path.join(root, "lib", "terminate.mjs")).href);
const { TERMINATE_SCHEMA, TERMINATE_NOT_CLAIMED, terminatePlan, applyTerminate, respawnReport } = mod;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== the declaration */

section("the declaration, and what it refuses to claim");

check("the schema is declared", TERMINATE_SCHEMA === "aikawamei-terminate/1", TERMINATE_SCHEMA);
check("it says a kill is not a neutralisation",
  TERMINATE_NOT_CLAIMED.some((s) => /kill removes the activity/.test(s)), JSON.stringify(TERMINATE_NOT_CLAIMED.length));
check("it says pids are reused",
  TERMINATE_NOT_CLAIMED.some((s) => /Pids are reused/.test(s)));
check("it does not claim to replace the four layers",
  TERMINATE_NOT_CLAIMED.some((s) => /replaces the four layers/.test(s)));

/* ================================================== matching */

section("a request names what it wants ended, and nothing is swept");

const procs = [
  { ProcessId: 100, Name: "updater.exe", ExecutablePath: "C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe" },
  { ProcessId: 200, Name: "updater.exe", ExecutablePath: "C:\\Program Files\\Legit\\updater.exe" },
  { ProcessId: 300, Name: "MpCmdRun.exe", ExecutablePath: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpCmdRun.exe" },
  { ProcessId: 400, Name: "svchost.exe", ExecutablePath: null },
  { ProcessId: 500, Name: "ksolaunch.exe", ExecutablePath: "C:\\Users\\me\\AppData\\Local\\Kingsoft\\WPS Office\\ksolaunch.exe" },
];

const byPath = terminatePlan(procs, { paths: ["C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe"] });
check("a path matches exactly one process, even though the name is shared",
  byPath.matched.length === 1 && byPath.matched[0].pid === 100, JSON.stringify(byPath.matched.map((m) => m.pid)));
check("the match says it was by path", byPath.matched[0]?.matched_by === "path");
check("the other process with the same name is untouched",
  !byPath.matched.some((m) => m.pid === 200), JSON.stringify(byPath.matched.map((m) => m.pid)));
check("case does not matter in a path",
  terminatePlan(procs, { paths: ["c:/users/ME/appdata/roaming/X/updater.exe"] }).matched.length === 1);

const byName = terminatePlan(procs, { names: ["updater"] });
check("a name matches both processes with that name", byName.matched.length === 2, JSON.stringify(byName.matched.map((m) => m.pid)));
check("and .exe is normalised on both sides",
  terminatePlan(procs, { names: ["updater.exe"] }).matched.length === 2);
check("a name matches a process whose path cannot be read", 
  terminatePlan(procs, { names: ["svchost"] }).matched.length === 1);

check("a request that matches nothing is reported, not resolved",
  terminatePlan(procs, { paths: ["C:\\nope\\x.exe"], names: ["nope"] }).matched.length === 0);
check("and both requests appear in unmatched with their kind",
  terminatePlan(procs, { paths: ["C:\\nope\\x.exe"], names: ["nope"] }).unmatched.length === 2,
  JSON.stringify(terminatePlan(procs, { paths: ["C:\\nope\\x.exe"], names: ["nope"] }).unmatched));
check("a process with a null path is not matched by a path request",
  !terminatePlan(procs, { paths: ["C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MpCmdRun.exe"] }).matched.some((m) => m.pid === 400));
check("pids that are not integers are dropped", terminatePlan([{ ProcessId: "x", Name: "a.exe" }], { names: ["a"] }).matched.length === 0);

section("the terminating process is refused, visibly");

const selfPlan = terminatePlan(procs, { names: ["updater"], selfPid: 100 });
check("its own pid is not in the kill list", !selfPlan.matched.some((m) => m.pid === 100), JSON.stringify(selfPlan.matched.map((m) => m.pid)));
check("and the refusal is reported rather than dropped",
  selfPlan.skipped.length === 1 && /doing the terminating/.test(selfPlan.skipped[0].why), JSON.stringify(selfPlan.skipped));
check("the other match still stands", selfPlan.matched.length === 1 && selfPlan.matched[0].pid === 200);

/* ================================================== carrying it out */

section("apply ends what the plan matched");

const io = (fails = []) => {
  const ended = [];
  return {
    ended,
    kill: (pid) => { if (fails.includes(pid)) throw new Error("access denied"); ended.push(pid); },
    list: null,
  };
};

const fake = io();
const result = applyTerminate(byName, fake);
check("both matched processes are ended", result.ended.length === 2, JSON.stringify(result.ended.map((e) => e.pid)));
check("the io really received both pids", fake.ended.join(",") === "100,200", fake.ended.join(","));
check("nothing is refused when nothing throws", result.refused.length === 0);

const partial = applyTerminate(byName, io([200]));
check("a kill that throws is reported, not swallowed",
  partial.refused.length === 1 && /access denied/.test(partial.refused[0].why), JSON.stringify(partial.refused));
check("the other termination still happened", partial.ended.length === 1 && partial.ended[0].pid === 100);

let threw = null;
try { applyTerminate(byName, {}); } catch (e) { threw = e; }
check("apply without a kill function refuses rather than reporting success", threw instanceof TypeError, String(threw));
check("a plan with nothing matched ends nothing",
  applyTerminate(terminatePlan(procs, { names: ["nope"] }), io()).ended.length === 0);

/* ================================================== the second look */

section("the look afterwards, which is what makes it neutralisation");

// The snapshot carries the path, because identity is taken from the path when it is readable. A
// fixture that omits it would match on the name alone, which is the weaker identity and not what a
// real process list looks like.
const before = procs.map((p) => ({ pid: p.ProcessId, name: p.Name, path: p.ExecutablePath }));
const quiet = respawnReport(before, [{ pid: 600, name: "other.exe", path: null }]);
check("nothing came back", quiet.respawned === false && quiet.fresh.length === 0, JSON.stringify(quiet.fresh));
check("and the reading says a kill is not proof", /not proof that nothing will start one later/.test(quiet.reading), quiet.reading);

// A restart is a DIFFERENT pid. The same pid in both snapshots would mean the kill never happened,
// so the fixture deliberately uses a new one.
const cameBack = respawnReport(before, [{ pid: 999, name: "updater.exe", path: "C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe" }]);
check("a new process with the same identity counts as a return", cameBack.respawned === true && cameBack.fresh.length === 1,
  JSON.stringify(cameBack.fresh));
check("and the reading names what to look for next",
  /what brings it back is the thing to find/.test(cameBack.reading) && /purge layer/.test(cameBack.reading), cameBack.reading);

const survivor = respawnReport(before, before);
check("the same pids are not a return -- they are the kill not having happened",
  survivor.respawned === false, JSON.stringify(survivor.fresh));

check("a snapshot that is not a list yields no return",
  respawnReport(before, null).respawned === false && respawnReport(null, null).respawned === false);

/* ================================================== summary */

console.log(`\n${fail ? "\u001b[31m" : "\u001b[32m"}${pass} passed, ${fail} failed\u001b[0m`);
if (fail) { for (const f of failures) console.log(`  - ${f}`); process.exit(1); }
