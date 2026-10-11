#!/usr/bin/env node
/**
 * Scope suite -- drives lib/scope.mjs, the guard that decides what may be read.
 *
 * Why this needs its own suite:
 *
 *   1. The whole module is one comparison, and the comparison has a classic way to be wrong: `/a/b`
 *      is a prefix of `/a/bc` and is not its parent. A guard built on `startsWith` therefore allows a
 *      sibling directory, and allows it silently -- the answer is "allowed", which is the answer for
 *      everything else. So every containment assertion below comes with the sibling case beside it,
 *      and the sibling case is the one that has to fail.
 *
 *   2. Two comparison modes exist because the platforms differ, and the suite cannot change which one
 *      it is running on. The mode is injected instead, so both are driven from this one machine --
 *      otherwise the case-sensitive branch would be exercised only in CI and the case-insensitive
 *      branch only here.
 *
 *   3. The module's claim is deliberately small: it refuses two shapes and otherwise trusts a
 *      declaration it cannot check. The assertions match that claim rather than a larger one -- there
 *      is no test asserting that ownership is established, because the module does not establish it.
 *
 * Hermeticity: paths that do not exist are compared literally, which is most of this file. The one
 * section that needs a real filesystem (a link pointing out of scope) builds its own temp tree and
 * removes it, and says so if the platform will not let it create the link.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const {
  SCOPE_SCHEMA, SCOPE_NOTICE,
  caseInsensitiveFor, classifyTarget, classifyTargets, containsPath, declaredScope,
  defaultScope, isNetworkPath, isOtherUsersProfile, normalizeForCompare, parseScopeText, scopeReport,
} = await import(pathToFileURL(path.join(root, "lib", "scope.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

const CI = { caseInsensitive: true };
const CS = { caseInsensitive: false };

/* ====================== A. containment ====================== */

section("A. what counts as inside");

check("a directory is inside itself", containsPath("/a/b", "/a/b", CS) === true);
check("a child is inside its parent", containsPath("/a/b", "/a/b/c", CS) === true);
check("a grandchild is inside too", containsPath("/a/b", "/a/b/c/d", CS) === true);
// The one that matters. `/a/bc` starts with `/a/b` and is a different directory.
check("a SIBLING with a shared prefix is NOT inside", containsPath("/a/b", "/a/bc", CS) === false);
check("...and neither is a sibling two levels away", containsPath("/a/b", "/a/bcd/e", CS) === false);
check("a parent is not inside its child", containsPath("/a/b/c", "/a/b", CS) === false);
check("the filesystem root contains anything", containsPath("/", "/a/b", CS) === true);

check("case is ignored when the platform ignores it", containsPath("/a/B", "/A/b/c", CI) === true);
check("case is honoured when the platform honours it", containsPath("/a/B", "/A/b/c", CS) === false);
check("the platform default is decided by the platform name",
  caseInsensitiveFor("win32") === true && caseInsensitiveFor("darwin") === true && caseInsensitiveFor("linux") === false);
check("normalisation folds only in the folding mode",
  normalizeForCompare("/A/b", CI) === normalizeForCompare("/a/B", CI)
  && normalizeForCompare("/A/b", CS) !== normalizeForCompare("/a/B", CS));

/* ====================== B. the two shapes ====================== */

section("B. the shapes refused without being asked");

check("a UNC path is a network path", isNetworkPath("\\\\server\\share\\x") === true);
check("forward-slash UNC counts too", isNetworkPath("//server/share") === true);
// The control: a device path is local, and refusing it would refuse a legitimate path.
check("a \\\\?\\ device path is NOT a network path", isNetworkPath("\\\\?\\C:\\x") === false);
check("a plain drive path is not one", isNetworkPath("C:\\x") === false);
check("a POSIX path is not one", isNetworkPath("/mnt/data") === false);

check("another user's profile is recognised", isOtherUsersProfile("C:\\Users\\someone-else\\x", { USERNAME: "me" }, CI) === true);
check("my own profile is not", isOtherUsersProfile("C:\\Users\\me\\x", { USERNAME: "me" }, CI) === false);
check("the same profile in different case is still mine", isOtherUsersProfile("c:\\users\\ME\\x", { USERNAME: "me" }, CI) === false);
check("a POSIX home of another user is recognised", isOtherUsersProfile("/home/other/x", { USER: "me" }, CS) === true);
check("a POSIX home of mine is not", isOtherUsersProfile("/home/me/x", { USER: "me" }, CS) === false);
check("a macOS home of another user is recognised", isOtherUsersProfile("/Users/other/x", { USER: "me" }, CS) === true);
check("an ordinary data directory is neither", isOtherUsersProfile("D:\\Data\\x", { USERNAME: "me" }, CI) === false);
check("with no current user named, it declines to judge", isOtherUsersProfile("C:\\Users\\x\\y", {}, CI) === false);

/* ====================== C. default mode ====================== */

section("C. the default scope");

const asUser = { USERNAME: "me", USER: "me" };
check("an ordinary local directory is allowed",
  classifyTarget("/data/project", defaultScope(asUser, CS), { env: asUser }).allowed === true);
check("a network path is refused, and the reason says why",
  (() => { const r = classifyTarget("//server/share/x", defaultScope(asUser, CS), { env: asUser });
           return r.allowed === false && /network/.test(r.reason); })());
check("another user's profile is refused, and the reason says why",
  (() => { const r = classifyTarget("C:\\Users\\someone-else\\x", defaultScope(asUser, CI), { env: asUser });
           return r.allowed === false && /different user/.test(r.reason); })());
check("my own profile is allowed",
  classifyTarget("C:\\Users\\me\\AppData\\x", defaultScope(asUser, CI), { env: asUser }).allowed === true);
check("an empty target is refused rather than treated as the working directory",
  classifyTarget("", defaultScope(asUser, CS), { env: asUser }).allowed === false);

/* ====================== D. declared mode ====================== */

section("D. the declared scope");

const declared = declaredScope(["/owned", "/also/owned"], CS);
check("a path inside a declared root is allowed", classifyTarget("/owned/x", declared).allowed === true);
check("a path in the second declared root is allowed too", classifyTarget("/also/owned/y", declared).allowed === true);
check("a path outside every declared root is refused",
  classifyTarget("/elsewhere", declared).allowed === false);
check("a sibling of a declared root is refused",
  classifyTarget("/owned-elsewhere", declared).allowed === false, "the prefix bug, at the guard");
check("the refusal names the root it was matched against",
  classifyTarget("/owned/x", declared).matchedBy === path.resolve("/owned"));
// Fail-closed: an operator who declares nothing owns nothing.
check("an empty declaration refuses everything",
  classifyTarget("/owned/x", declaredScope([], CS)).allowed === false);
check("...and so does a declaration of blanks", declaredScope(["", "  ", null]).roots.length === 0);

// `/owned/bc` is a CHILD of `/owned` and belongs in the allowed list; `/owned-elsewhere` is the
// sibling, and the sibling is the one the guard has to refuse. Putting the sibling in the list is
// the point of this assertion -- a version of it that only used children would pass for a guard
// built on a plain prefix comparison.
const split = classifyTargets(["/owned/a", "/owned-elsewhere/b", "/owned/bc", "/elsewhere"], declared);
check("classifyTargets keeps the allowed and refuses the rest",
  split.allowed.length === 2 && split.refused.length === 2, JSON.stringify(split));
check("a child of a declared root is allowed and a sibling is not",
  split.allowed.includes("/owned/bc") && split.refused.some((r) => r.target.endsWith("owned-elsewhere" + path.sep + "b")),
  JSON.stringify(split));
check("it names what it refused", split.refused.every((r) => typeof r.target === "string" && typeof r.reason === "string"));

/* ====================== E. the report ====================== */

section("E. what the response says about it");

const report = scopeReport(declared);
check("the report names the mode", report.mode === "declared" && report.source === "declared");
check("it lists the declared roots", report.declared_roots.length === 2, JSON.stringify(report.declared_roots));
check("it states the comparison it used", report.comparison === "case-sensitive", report.comparison);
check("it says the claim is NOT verified", report.verified === false);
check("it carries the notice", typeof report.notice === "string" && report.notice.length > 80);
check("the notice says ownership cannot be established here",
  /cannot|not a fact|nothing in a path/i.test(SCOPE_NOTICE), SCOPE_NOTICE);
check("the schema is versioned", /^aikawamei-scope\/\d+$/.test(SCOPE_SCHEMA), SCOPE_SCHEMA);
check("a default scope reports no declared roots", scopeReport(defaultScope(asUser, CS)).declared_roots.length === 0);
check("a default scope reports its rules", scopeReport(defaultScope(asUser, CS)).rules.length === 2);

const parsed = parseScopeText("# a machine I own\n/owned\n\n  /also/owned  # the second disk\n");
check("a scope manifest ignores comments and blanks", parsed.roots.length === 2, JSON.stringify(parsed.roots));
check("a trailing comment is stripped", parsed.roots[1] === path.resolve("/also/owned"), JSON.stringify(parsed.roots));
check("an empty manifest declares nothing", parseScopeText("").roots.length === 0);
check("a manifest tolerates nothing at all", parseScopeText(null).roots.length === 0);

/* ====================== F. a link pointing out ====================== */

section("F. a link that points out of scope");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-scope-"));
const outside = path.join(tmp, "outside");
const inside = path.join(tmp, "inside");
fs.mkdirSync(outside, { recursive: true });
fs.mkdirSync(inside, { recursive: true });
const link = path.join(inside, "escape");
let linked = false;
try {
  fs.symlinkSync(outside, link, "junction");
  linked = true;
} catch {
  try { fs.symlinkSync(outside, link, "dir"); linked = true; } catch { linked = false; }
}

if (linked) {
  const scoped = declaredScope([inside], CS);
  check("a link that resolves outside the declared root is refused",
    classifyTarget(link, scoped).allowed === false, JSON.stringify(classifyTarget(link, scoped)));
  check("the refusal says it resolves outside, so the reason is not mysterious",
    /resolves to/.test(classifyTarget(link, scoped).reason), classifyTarget(link, scoped).reason);
  check("the path it points AT is still refused on its own terms",
    classifyTarget(outside, scoped).allowed === false);
  check("a real child of the declared root is still allowed, so the guard is not refusing everything",
    classifyTarget(path.join(inside, "child"), scoped).allowed === true);
} else {
  console.log("  \u001b[90m[skip] this platform would not let the suite create a directory link,\u001b[0m");
  console.log("  \u001b[90m       so the escape case is NOT asserted in this run\u001b[0m");
}

try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}

/* ====================== summary ====================== */

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
