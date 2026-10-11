#!/usr/bin/env node
/**
 * Sessions suite -- drives lib/sessions.mjs and the five catalog entries behind aikawamei_sessions.
 *
 * Why this needs its own suite:
 *
 *   1. What this tool claims is a claim about a BOUND. The walk stops at a depth and at an entry
 *      count, and a bound asserted only from the inside -- "it found the file" -- passes just as
 *      well when the bound is wrong in the permissive direction. So every bound below is asserted
 *      as a PAIR: the case at the limit, and the case one step past it. The pair is what makes the
 *      assertion mean anything.
 *
 *   2. Two of those pairs are not reachable from a real fixture without building twenty thousand
 *      files, which would make the suite slow enough to eventually be skipped -- and a bound that
 *      is not tested is not a bound. The io layer is injected for exactly this, and it is used for
 *      exactly this.
 *
 *   3. The roots are DERIVED, which is a claim about what is NOT in the source. A hardcoded path
 *      would pass every functional test on the machine it was written on. What catches it is an
 *      environment that names nothing real: roots computed from it must equal its own list, with
 *      nothing from this machine leaking in.
 *
 *   4. Nothing here opens a file, and that is asserted structurally rather than promised: the
 *      evidence attached to a hit has exactly the keys the probe produces, so a future change that
 *      begins reading a cookie jar has to edit this suite to do it.
 *
 * Division of labour: checks.mjs owns the catalog and the probes, selftest owns the tool surface,
 *   matrix owns the output contract, coverage owns the traversal. This suite owns the sessions
 *   target: its roots, its bounds, and its refusal to look inside anything.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const sessions = await import(pathToFileURL(path.join(root, "lib", "sessions.mjs")).href);
const checks = await import(pathToFileURL(path.join(root, "lib", "checks.mjs")).href);
const core = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);

const {
  SESSIONS_SCHEMA, SESSIONS_BASE, SESSIONS_NOT_DETERMINED,
  defaultSessionRoots, planSessionRoots, gitWorktreeRootOf, annotateHits,
  scanSessionRoot, sessionsFindings, sessionsProbeContext,
} = sessions;
const { CHECK_CATALOG, checksFor, declaredFactPaths, evaluateBuiltins } = checks;
const { TOOLS, VERSION } = core;

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ====================== fixture ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-sessions-"));
const F = (...p) => path.join(base, ...p);
function put(rel, content = "x") {
  const full = F(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}
function mkdirp(rel) { fs.mkdirSync(F(rel), { recursive: true }); return F(rel); }

// A repository: everything under it must be reported as inside a working tree.
mkdirp("proj/.git");
put("proj/auth/storage_state.json", '{"cookies":[],"origins":[]}');
put("proj/auth/cookies.txt", "# Netscape HTTP Cookie File\n");
put("proj/login.har", '{"log":{"entries":[]}}');
put("proj/user-data/Default/Cookies", "sqlite");
put("proj/user-data/Local State", "{}");

// Outside any repository, and holding the two classes the fixture above does not: the
// camelCase Playwright spelling, and a report directory.
put("plain/storageState.json", '{"cookies":[]}');
put("plain/playwright-report/index.html", "<html></html>");

// A linked worktree: `.git` is a FILE here, not a directory, and both must count.
put("worktree/.git", "gitdir: /elsewhere/.git/worktrees/x");
put("worktree/sess/storage_state.json", '{"cookies":[]}');

// The depth bound gets a root of its own, so that the fixture the other assertions scan stays
// shallow. A tree that trips the bound would make every scan of `base` report a partial walk,
// and those assertions need a scan that IS complete to be the control against.
//
// The bound counts hops from the root's own children, so the deepest directory that gets LISTED
// is the one at depth `max_depth` (8): a directory seven hops down is listed, and the same
// directory eight hops down is not -- which means the file inside it is never seen. The pair
// below is that boundary, one file on each side of it, with the same name.
const deepBase = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-sessions-deep-"));
const D = (...p) => path.join(deepBase, ...p);
function putDeep(rel, content = "x") {
  const full = D(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}
const deepAt = (n) => Array.from({ length: n }, (_, i) => `d${i + 1}`).join("/");
putDeep(`under/${deepAt(7)}/storage_state.json`, '{"cookies":[]}');
putDeep(`under/${deepAt(8)}/storage_state.json`, '{"cookies":[]}');

/* ====================== A. roots are derived ====================== */

section("A. the roots come from the environment");

check("a synthetic environment is used verbatim, in order",
  JSON.stringify(defaultSessionRoots({ USERPROFILE: "/u/p", APPDATA: "/u/a", LOCALAPPDATA: "/u/l", TEMP: "/u/t" }, "/cwd"))
  === JSON.stringify(["/u/p", "/u/a", "/u/l", "/u/t", "/cwd"]),
  JSON.stringify(defaultSessionRoots({ USERPROFILE: "/u/p", APPDATA: "/u/a", LOCALAPPDATA: "/u/l", TEMP: "/u/t" }, "/cwd")));

check("a POSIX environment falls back to HOME",
  JSON.stringify(defaultSessionRoots({ HOME: "/home/x" }, "/cwd")) === JSON.stringify(["/home/x", "/cwd"]));

check("TMP serves when TEMP is absent",
  JSON.stringify(defaultSessionRoots({ HOME: "/h", TMP: "/t" }, "/cwd")) === JSON.stringify(["/h", "/t", "/cwd"]));

check("empty and missing values drop out rather than becoming a root",
  JSON.stringify(defaultSessionRoots({ HOME: "/h", APPDATA: "", LOCALAPPDATA: undefined }, "/cwd"))
  === JSON.stringify(["/h", "/cwd"]));

// The anti-hardcoding assertion. With nothing in the environment there is nothing to derive, and
// a fallback to a machine-specific path would show up here as an extra entry.
check("an empty environment yields only the working directory, so nothing is hardcoded",
  JSON.stringify(defaultSessionRoots({}, "/cwd")) === JSON.stringify(["/cwd"]),
  JSON.stringify(defaultSessionRoots({}, "/cwd")));

check("the working directory is among the defaults",
  defaultSessionRoots({ HOME: "/h" }, "/somewhere").includes("/somewhere"));

/* ====================== B. root planning ====================== */

section("B. overlapping roots are ordered and named, not double-counted");

const planned = planSessionRoots(["/a", "/a/b", "/a", "/c"]);
check("a repeated root is not scanned twice", planned.scanned.filter((r) => r === path.resolve("/a")).length === 1);
check("a nested root is skipped", planned.skipped.length === 1 && planned.skipped[0].covered_by === path.resolve("/a"),
  JSON.stringify(planned.skipped));
check("the skipped root is named", planned.skipped[0].root === path.resolve("/a/b"), JSON.stringify(planned.skipped));
check("a sibling root is NOT skipped", planned.scanned.includes(path.resolve("/c")), JSON.stringify(planned.scanned));
check("non-strings and empty strings are ignored", JSON.stringify(planSessionRoots([null, "", 7, "/a"]).scanned) === JSON.stringify([path.resolve("/a")]));
check("a non-array is tolerated", JSON.stringify(planSessionRoots(null)) === JSON.stringify({ scanned: [], skipped: [] }));

/* ====================== C. the repository question ====================== */

section("C. whether a hit sits inside a working tree");

check("a .git DIRECTORY above the file is found", gitWorktreeRootOf(F("proj", "auth")) === F("proj"),
  String(gitWorktreeRootOf(F("proj", "auth"))));
check("a .git FILE counts too, which is what a linked worktree has", gitWorktreeRootOf(F("worktree", "sess")) === F("worktree"),
  String(gitWorktreeRootOf(F("worktree", "sess"))));
check("no repository above the file reports null", gitWorktreeRootOf(F("plain")) === null, String(gitWorktreeRootOf(F("plain"))));
check("the walk terminates at the filesystem root rather than looping", gitWorktreeRootOf(path.parse(base).root) !== undefined);

const trueIo = { exists: () => true };
check("the walk is bounded, not unbounded", gitWorktreeRootOf(F("a", "b"), trueIo) !== undefined);
// Every candidate path this function tests has ".git" APPENDED to it, so a predicate phrased as
// "the path ends in .git" is true of the file's own directory and answers yes without ever
// looking upward. The predicate below names one exact path instead, so the walk has to actually
// arrive there -- which is the only way this assertion tests the walk rather than the predicate.
const onlyWorktree = { exists: (p) => p === path.join(F("worktree"), ".git") };
check("an injected io is what decides the answer",
  gitWorktreeRootOf(F("plain"), onlyWorktree) === null
  && gitWorktreeRootOf(F("worktree", "sess"), onlyWorktree) === F("worktree")
  && gitWorktreeRootOf(F("plain"), trueIo) !== null,
  `${gitWorktreeRootOf(F("plain"), onlyWorktree)} / ${gitWorktreeRootOf(F("worktree", "sess"), onlyWorktree)}`);

check("annotation leaves a finding without entries alone",
  annotateHits([{ evidence: null }], trueIo).length === 1);
check("annotation leaves a finding with a non-array entries field alone",
  annotateHits([{ evidence: { root: "/r", entries: "no" } }], trueIo)[0].evidence.entries === "no");

/* ====================== D. the catalog entries ====================== */

section("D. the five entries the target declares");

const sessEntries = checksFor({ target: "sessions" }).checks;
check("the target declares five checks", sessEntries.length === 5, String(sessEntries.length));
check("every one of them is a builtin", sessEntries.every((e) => e.kind === "builtin"));
check("every one of them probes the tree", sessEntries.every((e) => e.probe === "tree-match"));
check("every one of them addresses the sessions base", sessEntries.every((e) => e.probe_args?.base === SESSIONS_BASE));
check("every one of them states a boundary", sessEntries.every((e) => typeof e.does_not_cover === "string" && e.does_not_cover.length > 40));
check("every one of them observes something", sessEntries.every((e) => typeof e.observes === "string" && e.observes.length > 10));
check("every one of them declares exactly one allowed severity",
  sessEntries.every((e) => Array.isArray(e.severities) && e.severities.length === 1), JSON.stringify(sessEntries.map((e) => e.severities)));
check("every one of them names a fact", sessEntries.every((e) => typeof e.fact === "string" && e.fact.length > 0));
check("their ids are namespaced to the target", sessEntries.every((e) => e.id.startsWith("sessions-")));

// Control: target filtering is real, so the five above are not simply "all builtins".
check("another target does not contain them", checksFor({ target: "handoff" }).checks.every((e) => !e.id.startsWith("sessions-")));

const factPaths = declaredFactPaths();
const dupes = factPaths.filter((d, i) => factPaths.findIndex((x) => x.fact === d.fact) !== i);
check("no two checks anywhere in the catalog share a fact slot", dupes.length === 0, JSON.stringify(dupes));

check("the tool exists, is named for the surface, and takes roots",
  TOOLS.some((t) => t.name === "aikawamei_sessions" && t.inputSchema?.properties?.roots?.type === "array"));

/* ====================== E. a real scan ====================== */

section("E. a scan of the fixture");

const one = scanSessionRoot(base);
const ids = one.findings.map((f) => f.id);
check("all five classes are reported", new Set(ids).size === 5, JSON.stringify(ids));
check("a bounded walk of this fixture is not truncated", one.truncated === false);
check("the scan reports how much it looked at", one.scanned_entries > 10, String(one.scanned_entries));

const byId = Object.fromEntries(one.findings.map((f) => [f.id, f]));
const hits = (id) => (byId[id]?.evidence?.entries ?? []).map((e) => e.path);
// The repository answer, asserted in BOTH directions: a positive that could also come from a
// function that always returns something, and a negative that could also come from one that
// always returns null.
//
// `??` is deliberately NOT used to default this: it falls back on null as well as on undefined,
// which would turn "found the hit, and it is outside any repository" into the same value as
// "never found the hit at all" -- the exact conflation this pair exists to prevent.
const gitOf = (id, needle) => {
  const hit = (byId[id]?.evidence?.entries ?? []).find((e) => e.path.includes(needle));
  return hit ? hit.git_root : "NOT-FOUND";
};

check("the plaintext export class finds the Playwright spelling and the jar",
  hits("sessions-plaintext-session-export").some((p) => p.endsWith("auth/storage_state.json"))
  && hits("sessions-plaintext-session-export").some((p) => p.endsWith("plain/storageState.json"))
  && hits("sessions-plaintext-session-export").some((p) => p.endsWith("cookies.txt")),
  JSON.stringify(hits("sessions-plaintext-session-export")));
check("the archive class finds the HAR", hits("sessions-http-archive").some((p) => p.endsWith("login.har")));
check("the profile-store class finds the cookie store and the key beside it",
  hits("sessions-profile-store").some((p) => p.endsWith("Default/Cookies"))
  && hits("sessions-profile-store").some((p) => p.endsWith("Local State")),
  JSON.stringify(hits("sessions-profile-store")));
check("the profile-directory class matches a directory", hits("sessions-profile-dir").some((p) => p.endsWith("user-data/")));
check("the artifact class finds the report directory", hits("sessions-automation-artifact").some((p) => p.endsWith("playwright-report/")));

// The repository answer, asserted in BOTH directions: a positive that could also come from a
// function that always returns something, and a negative that could also come from one that
// always returns null.
check("a hit inside a repository names the repository", gitOf("sessions-http-archive", "login.har") === F("proj"),
  String(gitOf("sessions-http-archive", "login.har")));
check("a hit inside a LINKED worktree names it too", gitOf("sessions-plaintext-session-export", "worktree/sess") === F("worktree"),
  String(gitOf("sessions-plaintext-session-export", "worktree/sess")));
check("a hit outside any repository reports null, not a guess",
  gitOf("sessions-plaintext-session-export", "plain/storageState.json") === null,
  String(gitOf("sessions-plaintext-session-export", "plain/storageState.json")));

// The structural assertion behind "it never opens a file".
const keySets = one.findings.flatMap((f) => (f.evidence.entries ?? []).map((e) => Object.keys(e).sort().join(",")));
check("a hit carries a path, a size, a time, an age and a repository -- and nothing else",
  keySets.length > 0 && keySets.every((k) => k === "age_days,git_root,mtime,path,size"), JSON.stringify([...new Set(keySets)]));

check("the severities come from the declared sets",
  byId["sessions-http-archive"].severity === "critical"
  && byId["sessions-plaintext-session-export"].severity === "critical"
  && byId["sessions-profile-store"].severity === "warn"
  && byId["sessions-profile-dir"].severity === "warn"
  && byId["sessions-automation-artifact"].severity === "info");

check("no rendered title or detail leaves a placeholder unresolved",
  one.findings.every((f) => !/\{[A-Za-z_]/.test(f.title) && !/\{[A-Za-z_]/.test(f.detail)),
  JSON.stringify(one.findings.filter((f) => /\{[A-Za-z_]/.test(f.title + f.detail)).map((f) => f.title)));

/* ====================== F. the bounds, as pairs ====================== */

section("F. the depth bound and the entry bound");

const deepOne = scanSessionRoot(deepBase);
const deepHits = (deepOne.findings.find((f) => f.id === "sessions-plaintext-session-export")?.evidence?.entries ?? []).map((e) => e.path);
const foundAt7 = deepHits.some((p) => p.includes(`${deepAt(7)}/storage_state.json`));
const foundAt8 = deepHits.some((p) => p.includes(`${deepAt(8)}/storage_state.json`));
check("a file at the depth limit is found", foundAt7);
check("a file one hop past it is not", !foundAt8, JSON.stringify(deepHits));

// The depth stop has to be REPORTED, not merely performed. Until it was, a walk that stopped at
// its depth bound reported `truncated: false`, which reads as "the tree was covered" -- the one
// thing the probe's own comment says must never happen. A root that is deep and a root that is
// shallow are asserted together, because a flag that is always true is as useless as one that is
// always false.
check("a walk that stopped at its depth bound says so",
  deepOne.truncated === true && deepOne.depth_limited === true, JSON.stringify({ t: deepOne.truncated, d: deepOne.depth_limited }));
check("a shallow walk is not flagged in either direction",
  one.truncated === false && one.depth_limited === false, JSON.stringify({ t: one.truncated, d: one.depth_limited }));

// The entry budget, driven through an injected filesystem. `max_entries` is 20000 in the catalog,
// so the pair is 20000 (fits) and 20001 (does not). A matching name is present in both, because a
// walk that finds nothing returns no finding at all and would hide the truncation flag.
function flatIo(count) {
  const entries = [{ name: "storage_state.json", isDirectory: () => false }];
  for (let i = 1; i < count; i += 1) entries.push({ name: `filler${i}.txt`, isDirectory: () => false });
  return {
    exists: () => true,
    listDir: () => entries,
    statOf: () => ({ size: 12, mtime: new Date(0) }),
  };
}
const atBudget = evaluateBuiltins("sessions", sessionsProbeContext("/fake", flatIo(20000)));
const overBudget = evaluateBuiltins("sessions", sessionsProbeContext("/fake", flatIo(20001)));
check("a walk of exactly the entry budget is not flagged as truncated",
  atBudget.length > 0 && atBudget.every((f) => f.evidence.truncated === false), JSON.stringify(atBudget.map((f) => f.evidence.truncated)));
check("a walk one entry past it IS flagged",
  overBudget.length > 0 && overBudget.some((f) => f.evidence.truncated === true), JSON.stringify(overBudget.map((f) => f.evidence.truncated)));
check("the injected filesystem is what was walked", overBudget[0].evidence.scanned === 20000, String(overBudget[0].evidence.scanned));

check("sessionsFindings tolerates a missing root", JSON.stringify(sessionsFindings("")) === JSON.stringify([]));

// Age, asserted against a fixed clock rather than the wall clock. The pair is a file from thirty
// days before that instant and one from the instant itself; the third case is a hit the probe
// could not stat, where a zero would be a claim and null is the truth.
const at = Date.UTC(2026, 0, 31, 12, 0, 0);
const day = 86400000;
const aged = annotateHits([{ evidence: { root: "/r", entries: [
  { path: "old/storage_state.json", size: 1, mtime: new Date(at - 30 * day).toISOString() },
  { path: "new/storage_state.json", size: 1, mtime: new Date(at).toISOString() },
  { path: "unstatted/storage_state.json", size: null, mtime: null },
] } }], { exists: () => false }, at);
check("a hit from thirty days before the clock reads as thirty days old", aged[0].evidence.entries[0].age_days === 30,
  String(aged[0].evidence.entries[0].age_days));
check("a hit from the clock itself reads as zero, not as absent", aged[0].evidence.entries[1].age_days === 0,
  String(aged[0].evidence.entries[1].age_days));
check("a hit with no timestamp has no age rather than an assumed one", aged[0].evidence.entries[2].age_days === null,
  String(aged[0].evidence.entries[2].age_days));
check("every hit in a real scan carries an age", one.findings.flatMap((f) => f.evidence.entries).every((e) => Number.isInteger(e.age_days) && e.age_days >= 0),
  JSON.stringify(one.findings.flatMap((f) => f.evidence.entries).map((e) => e.age_days).slice(0, 6)));

/* ====================== G. the tool ====================== */

section("G. the aikawamei_sessions tool");

const tool = TOOLS.find((t) => t.name === "aikawamei_sessions");

const res = await tool.execute({ roots: [base] });
check("the response names the schema", res.schema === SESSIONS_SCHEMA);
check("the response carries the version", res.tool_version === VERSION);
check("the finding set conforms to the declared catalog", res.checks?.conformant === true, JSON.stringify(res.checks?.unknown));
check("the catalog size is reported from the catalog itself", res.checks.declared === CHECK_CATALOG.length, String(res.checks.declared));
check("every scanned root is named", res.roots.length === 1 && res.roots[0].root === base, JSON.stringify(res.roots));
check("the tally counts what is reported",
  Object.values(res.tally).reduce((a, b) => a + b, 0) === res.findings.length, JSON.stringify(res.tally));
// BOUNDARY_NOTICE is an array of statements rather than one string: the project's rule is that a
// boundary claim which is false in its first line is worse than no claim at all, so the notice
// is four lines carrying four separate jobs.
check("the boundary notice travels with the answer",
  Array.isArray(res.boundary_notice) && res.boundary_notice.length === 4
  && res.boundary_notice.every((l) => typeof l === "string" && l.length > 30),
  JSON.stringify(res.boundary_notice));
check("the undetermined questions travel with the answer too",
  res.not_determined.length === 3 && res.not_determined.every((q) => q.question && q.answerable_by && q.why_not));
check("one of them names the command that answers it",
  res.not_determined.some((q) => q.answerable_by.includes("check-ignore")));
check("the findings are ordered by severity, worst first",
  res.findings.map((f) => f.severity).join(",").startsWith("critical"), res.findings.map((f) => f.severity).join(","));

const crit = await tool.execute({ roots: [base], min_severity: "critical" });
check("a severity filter narrows the findings", crit.findings.length === 2 && crit.findings.every((f) => f.severity === "critical"),
  JSON.stringify(crit.findings.map((f) => f.severity)));
check("the filter is echoed back", crit.applied_filter.min_severity === "critical");

const meta = await tool.execute({ roots: [base], layer: "metadata" });
check("a layer filter narrows to that layer", meta.findings.length === 2 && meta.findings.every((f) => f.layer === "metadata"),
  JSON.stringify(meta.findings.map((f) => f.layer)));

const missing = await tool.execute({ roots: [F("does-not-exist")] });
check("a root that does not exist is reported as absent rather than omitted",
  missing.roots.length === 1 && missing.roots[0].exists === false && missing.findings.length === 0,
  JSON.stringify(missing.roots));

const nested = await tool.execute({ roots: [base, F("proj")] });
check("a nested root is reported as skipped, with what covered it",
  nested.roots_skipped.length === 1 && nested.roots_skipped[0].covered_by === base, JSON.stringify(nested.roots_skipped));
check("the nested root produced no second copy of the findings",
  nested.findings.find((f) => f.id === "sessions-http-archive").evidence.matched === 1,
  String(nested.findings.find((f) => f.id === "sessions-http-archive").evidence.matched));

const fakeEnv = defaultSessionRoots({}, F("does-not-exist"));
check("a root list with nothing in it but a missing path still answers",
  (await tool.execute({ roots: fakeEnv })).findings.length === 0);

// A file where a directory was expected must read as absent, not as an empty directory.
const notADir = await tool.execute({ roots: [F("plain", "login.har")] });
check("a file passed as a root is absent, not scanned",
  notADir.roots[0].exists === false && notADir.findings.length === 0, JSON.stringify(notADir.roots));

// The command line has to be able to say what the tool can say. A parser that produces scalars
// only accepts `--roots X --roots Y` and then ignores both, so the scan quietly runs against the
// environmental defaults -- an argument taken and not obeyed. This is driven through the real
// entry point rather than through the parser, because the parser is not what a caller uses.
const cliOut = execFileSync(process.execPath, [
  path.join(root, "cli", "index.mjs"), "aikawamei_sessions",
  "--roots", F("proj"), "--roots", F("plain"),
], { encoding: "utf8" });
const cliRes = JSON.parse(cliOut);
check("a repeated list argument on the command line is obeyed",
  cliRes.roots.length === 2 && cliRes.roots[0].root === F("proj") && cliRes.roots[1].root === F("plain"),
  JSON.stringify(cliRes.roots.map((r) => r.root)));
// Findings are produced per (root, class), so the count for two roots is not the count for one
// root containing them. The two are compared against each other instead, which is the property that
// actually has to hold: the command line reaches what the tool reaches.
const sameTwoRoots = await tool.execute({ roots: [F("proj"), F("plain")] });
check("the command line reaches the same findings the tool does",
  cliRes.findings.map((f) => f.id).join(",") === sameTwoRoots.findings.map((f) => f.id).join(","),
  `${cliRes.findings.map((f) => f.id).join(",")} vs ${sameTwoRoots.findings.map((f) => f.id).join(",")}`);

/* ====================== H. the record it can leave ====================== */

section("H. the optional record");

const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-sessions-vault-"));
const chainFile = path.join(vaultDir, "chain.jsonl");
const vault = await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href);
const vaultTool = TOOLS.find((t) => t.name === "aikawamei_vault");

// Read-only is the default, and it is asserted rather than assumed: no vault named means no file,
// and no field in the response either.
const noVault = await tool.execute({ roots: [F("proj")] });
check("a scan with no vault writes nothing", !fs.existsSync(chainFile) && noVault.vault === undefined,
  JSON.stringify(noVault.vault));

// Without a passphrase the record carries counts and nothing else. This is the shape that has to
// hold when the paths belong to someone else, so it is asserted on the RAW BYTES rather than on a
// parsed field: a leak would be a leak wherever in the line it sat.
delete process.env.AIKAWAMEI_VAULT_PASSPHRASE;
const counted = await tool.execute({ roots: [F("proj")], vault: chainFile });
const rawCounted = fs.readFileSync(chainFile, "utf8");
check("a named vault is written", counted.vault?.length === 1 && fs.existsSync(chainFile), JSON.stringify(counted.vault));
check("it is not sealed when no passphrase is set", counted.vault.sealed === false);
check("the record names no path at all",
  !/storage_state|cookies\.txt|login\.har|user-data|proj|auth/.test(rawCounted), rawCounted.slice(0, 160));
check("...and it still says what happened", /finding\(s\)/.test(rawCounted), rawCounted.slice(0, 160));
check("the chain verifies without the passphrase", vault.verifyFile(chainFile).ok === true);

// With a passphrase the paths are inside the sealed payload: recoverable by the holder of the key,
// absent from the cleartext. Both halves are asserted, because either alone is a weaker claim.
process.env.AIKAWAMEI_VAULT_PASSPHRASE = "a passphrase for the suite";
const sealedRun = await tool.execute({ roots: [F("proj")], vault: chainFile });
const rawSealed = fs.readFileSync(chainFile, "utf8");
check("a second run appends rather than replacing", sealedRun.vault.length === 2, JSON.stringify(sealedRun.vault));
check("it reports the record as sealed", sealedRun.vault.sealed === true);
check("the cleartext still names no path",
  !/storage_state|cookies\.txt|login\.har|user-data|proj|auth/.test(rawSealed), rawSealed.slice(0, 200));
const openedRecord = vault.openValue(process.env.AIKAWAMEI_VAULT_PASSPHRASE, JSON.parse(rawSealed.trim().split("\n")[1]).sealed);
check("the sealed payload holds the paths the cleartext does not",
  JSON.stringify(openedRecord).includes("storage_state") || JSON.stringify(openedRecord).includes("login.har"),
  JSON.stringify(openedRecord).slice(0, 160));
check("and it is unreadable without the passphrase", (() => {
  try { vault.openValue("not the passphrase", JSON.parse(rawSealed.trim().split("\n")[1]).sealed); return false; } catch { return true; }
})());
delete process.env.AIKAWAMEI_VAULT_PASSPHRASE;

// The tool that checks a chain, and the receipt it hands out.
const verified = await vaultTool.execute({ path: chainFile });
check("the vault tool verifies a chain with no passphrase",
  verified.ok === true && verified.length === 2, JSON.stringify(verified).slice(0, 160));
check("it returns the receipt a later check needs",
  verified.receipt?.length === 2 && typeof verified.receipt?.head === "string");
check("it states what it cannot see", typeof verified.does_not_cover === "string" && verified.does_not_cover.length > 40);
check("a path with no chain is an answer, not a crash",
  (await vaultTool.execute({ path: path.join(vaultDir, "absent.jsonl") })).exists === false);
check("no path at all is an error", typeof (await vaultTool.execute({})).error === "string");
// An unreadable path is reported as an error rather than as an empty chain: "there is no record
// here" and "I could not read what is here" are different answers, and only the first one is one.
const notAFile = path.join(vaultDir, "a-directory");
fs.mkdirSync(notAFile, { recursive: true });
check("a path that cannot be read is reported as an error, not as an empty chain",
  typeof (await vaultTool.execute({ path: notAFile })).error === "string",
  JSON.stringify(await vaultTool.execute({ path: notAFile })).slice(0, 120));

// Truncation through the tool, with the matching case as the control.
const shortened = path.join(vaultDir, "short.jsonl");
fs.writeFileSync(shortened, rawSealed.trim().split("\n")[0] + "\n");
check("a cut chain passes on its own terms", (await vaultTool.execute({ path: shortened })).ok === true);
check("and is caught against the receipt the tool itself handed out",
  (await vaultTool.execute({ path: shortened, expect_length: verified.receipt.length })).truncation_detected === true);
check("the untruncated chain passes the same check",
  (await vaultTool.execute({ path: chainFile, expect_length: verified.receipt.length })).ok === true);

try { fs.rmSync(vaultDir, { recursive: true, force: true }); } catch {}

/* ====================== I. what it will not look at ====================== */

section("I. the scope guard, where it meets a scan");

const scoped = await tool.execute({ roots: [F("proj")] });
check("an ordinary local root is allowed by the default scope",
  scoped.roots.length === 1 && scoped.refused.length === 0, JSON.stringify(scoped.refused));
check("the response states the scope it used",
  scoped.scope?.mode === "default" && scoped.scope?.verified === false, JSON.stringify(scoped.scope));
check("...and says the claim is not verified by this tool",
  /cannot|not a fact|nothing in a path/i.test(scoped.scope?.notice ?? ""), String(scoped.scope?.notice).slice(0, 90));

const network = await tool.execute({ roots: ["//server/share/x", F("proj")] });
check("a network root is refused", network.refused.length === 1, JSON.stringify(network.refused));
check("...with a reason that names the problem", /network/.test(network.refused[0]?.reason ?? ""), JSON.stringify(network.refused));
check("...and it is NOT scanned, while the allowed root still is",
  network.roots.length === 1 && network.roots[0].root === F("proj"), JSON.stringify(network.roots));

const narrowed = await tool.execute({ roots: [F("proj"), F("plain")], scope: [F("proj")] });
check("a declared scope refuses a root outside it",
  narrowed.refused.length === 1 && narrowed.refused[0].target === F("plain"), JSON.stringify(narrowed.refused));
check("...and still scans the one inside it", narrowed.roots.length === 1 && narrowed.roots[0].root === F("proj"));
check("the declaration is reported back so it can be checked",
  JSON.stringify(narrowed.scope?.declared_roots) === JSON.stringify([F("proj")]), JSON.stringify(narrowed.scope?.declared_roots));
// Fail-closed, and NOT a fallback to the default: a caller who named a scope and gave nothing owns
// nothing, and the response says so visibly (an empty declared_roots list and one refusal with a
// reason) rather than quietly applying a wider scope than the one that was asked for. Quietly
// ignoring an argument is the failure this project treats as worse than refusing it.
const blankScope = await tool.execute({ roots: [F("proj")], scope: ["  "] });
check("a declaration of nothing refuses everything rather than widening back to the default",
  blankScope.roots.length === 0 && blankScope.refused.length === 1 && blankScope.scope.declared_roots.length === 0,
  JSON.stringify({ roots: blankScope.roots, refused: blankScope.refused, declared: blankScope.scope.declared_roots }));

// The refusal has to reach the record too: an operator reading the chain later should see that the
// run was pointed somewhere and declined. The count is in the clear and the path is not, which is
// the same split the finding paths get.
process.env.AIKAWAMEI_VAULT_PASSPHRASE = "a passphrase for the suite";
const refusedDir = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-sessions-refused-"));
const refuseChain = path.join(refusedDir, "chain.jsonl");
const refusedRun = await tool.execute({ roots: [F("proj"), "//server/share/x"], vault: refuseChain });
const rawRefusal = fs.readFileSync(refuseChain, "utf8");
check("a refusal is counted in the record", /1 refused/.test(rawRefusal), rawRefusal.slice(0, 180));
check("...and the refused path is NOT in the clear",
  !rawRefusal.includes("server") && !rawRefusal.includes("share"), rawRefusal.slice(0, 180));
const openedRefusal = vault.openValue(process.env.AIKAWAMEI_VAULT_PASSPHRASE, JSON.parse(rawRefusal.trim()).sealed);
check("...but it is inside the sealed payload, so the record is still complete",
  JSON.stringify(openedRefusal.refused).includes("server"), JSON.stringify(openedRefusal.refused));
check("the sealed payload records which scope was in force",
  openedRefusal.scope?.mode === "default", JSON.stringify(openedRefusal.scope));
delete process.env.AIKAWAMEI_VAULT_PASSPHRASE;
check("the refusal is reported in the response as well",
  refusedRun.refused.length === 1 && refusedRun.roots.length === 1, JSON.stringify(refusedRun.refused));
try { fs.rmSync(refusedDir, { recursive: true, force: true }); } catch {}

/* ====================== summary ====================== */

try {
  fs.rmSync(base, { recursive: true, force: true });
  fs.rmSync(deepBase, { recursive: true, force: true });
  console.log("\n  \u001b[90mtemporary fixtures cleaned up\u001b[0m");
} catch {}

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
