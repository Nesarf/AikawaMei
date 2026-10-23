#!/usr/bin/env node
/**
 * Neutralise suite -- drives lib/neutralize.mjs, the module that turns findings into an order of moves.
 *
 * What this is really testing
 * ---------------------------
 *   1. THE ORDER IS DERIVED, AND BOTH DERIVATIONS ARE ASSERTED. A list built from a recorded
 *      autostart must start with the outbound block; a list built from a plaintext session export
 *      with no autostart must start with revocation. A module that always emitted one order would
 *      pass a single-sided test and be wrong half the time.
 *
 *   2. NOTHING HERE EXECUTES. That is asserted structurally: the module's source is searched for
 *      the process, registry and firewall symbols it must not contain. A tool that emitted
 *      `New-NetFirewallRule` as text and also ran it would be indistinguishable from one that only
 *      printed it, from the outside.
 *
 *   3. THE UNRESOLVED LIST IS A REAL OUTPUT, not a leftover. A command line with no path in it, a
 *      mechanism with no generic removal, a program that starts from somewhere only administrators
 *      can write -- each lands in `unresolved` with the command that would answer it, rather than
 *      being dropped.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const mod = await import(pathToFileURL(path.join(root, "lib", "neutralize.mjs")).href);
const {
  NEUTRALIZE_SCHEMA, NEUTRALIZE_LAYERS, NEUTRALIZE_NOT_CLAIMED, PURGE_BY_SOURCE,
  exeFromCommand, looksUserWritablePath, severRule, disableMoves, neutralizePlan,
} = mod;
const revoke = await import(pathToFileURL(path.join(root, "lib", "revoke.mjs")).href);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== the shape */

section("the four moves are declared, and none of them runs");

check("the schema is declared", NEUTRALIZE_SCHEMA === "aikawamei-neutralize/1", NEUTRALIZE_SCHEMA);
check("four layers, in the order they apply to something self-restoring",
  NEUTRALIZE_LAYERS.join(",") === "sever,disable,purge,revoke", NEUTRALIZE_LAYERS.join(","));
check("the not-claimed list says nothing was carried out",
  NEUTRALIZE_NOT_CLAIMED.some((s) => /executes nothing/.test(s)), JSON.stringify(NEUTRALIZE_NOT_CLAIMED));
check("every purge recipe states its cost and whether it can be undone",
  Object.values(PURGE_BY_SOURCE).every((r) => r.what && typeof r.command === "function" && r.cost && typeof r.reversible === "boolean"),
  JSON.stringify(Object.keys(PURGE_BY_SOURCE).filter((k) => !(PURGE_BY_SOURCE[k].cost))));

// The structural claim: this module contains no way to act on the machine. The pattern names the
// calls that START a process; `RegExp.exec` is not one of them, and matching a bare `exec(` would
// have flagged the string matching this very module does (`/^"([^"]+)"/.exec(s)`) as a subprocess.
const source = fs.readFileSync(path.join(root, "lib", "neutralize.mjs"), "utf8");
const ACTS = /\b(?:execSync|execFileSync|execFile|spawnSync|spawn)\s*\(|child_process/;
check("the module contains no call that would act on the machine",
  !ACTS.test(source), (ACTS.exec(source) ?? [""])[0]);
check("it does not import a process API at all, and keeps its commands in string fields",
  !/node:child_process/.test(source) && /command:/.test(source));

/* ================================================== reading a command line */

section("a command line is reduced to the program it names");

check("a quoted path", exeFromCommand('"C:\\Users\\x\\AppData\\Roaming\\a.exe" --silent') === "C:\\Users\\x\\AppData\\Roaming\\a.exe",
  String(exeFromCommand('"C:\\Users\\x\\AppData\\Roaming\\a.exe" --silent')));
check("an unquoted path with an argument", exeFromCommand("C:\\Windows\\System32\\x.exe -k") === "C:\\Windows\\System32\\x.exe",
  String(exeFromCommand("C:\\Windows\\System32\\x.exe -k")));
check("a bare name is not a path", exeFromCommand("cmd.exe /c start") === null, String(exeFromCommand("cmd.exe /c start")));
// Measured on this machine: the first run emitted a firewall rule whose -Program was a DIRECTORY,
// taken from a startup folder entry. Both of these must yield nothing rather than a plausible command.
check("a directory is not an executable",
  exeFromCommand("C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start") === null, "directory accepted");
check("a shortcut is not an executable",
  exeFromCommand("C:\\Users\\me\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.lnk") === null, "lnk accepted");
check("a launcher with an executable extension is", exeFromCommand("C:\\x\\y.bat") === "C:\\x\\y.bat", String(exeFromCommand("C:\\x\\y.bat")));
check("an empty command yields nothing", exeFromCommand("") === null && exeFromCommand(null) === null);
check("a user-writable location is recognised",
  looksUserWritablePath("C:\\Users\\me\\AppData\\Roaming\\x\\a.exe") && looksUserWritablePath("C:\\ProgramData\\x\\a.exe"));
check("a standard location is not", !looksUserWritablePath("C:\\Program Files\\a\\a.exe"));

/* ================================================== the moves themselves */

section("each move carries its cost");

const sev = severRule("C:\\Users\\me\\AppData\\Roaming\\a.exe");
check("the sever rule blocks outbound for that program, not for an address",
  /-Direction Outbound/.test(sev.command) && /-Program "C:\\Users\\me/.test(sev.command), sev.command);
check("it says why a program rule comes before an address list", /knowledge of the pool/.test(sev.action), sev.action);
check("it says the rule can be removed", sev.reversible === true && /Remove-NetFirewallRule/.test(sev.cost));

const off = disableMoves("C:\\Users\\me\\AppData\\Roaming\\a.exe");
check("three ways to disable, all reversible", off.length === 3 && off.every((m) => m.reversible === true), String(off.length));
check("denying execute keeps the bytes", off.some((m) => /icacls/.test(m.command) && /leaving the bytes in place/.test(m.action)));
check("renaming defeats a recorded path and says so", off.some((m) => /Rename-Item/.test(m.command) && /recorded path/.test(m.why)));
check("moving names a destination outside every autostart path", off.some((m) => /quarantine/.test(m.command)));

/* ================================================== the order */

section("the order is derived from what was found");

const persistence = [
  { source: "run-key", subject: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", target: "C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe", at: "2026-10-20T10:00:00Z" },
  { source: "task", subject: "\\Microsoft\\Windows\\UpdaterTask", target: "C:\\Users\\me\\AppData\\Local\\Temp\\t.exe", at: "2026-10-20T10:05:00Z" },
];
const withPersistence = neutralizePlan({ persistence });
check("a recorded autostart puts the outbound block first",
  withPersistence.order[0] === "sever" && withPersistence.order.join(",") === "sever,disable,purge,revoke",
  withPersistence.order.join(","));
check("and the reason names the thing that restarts",
  /starting itself/.test(withPersistence.whyThisOrder), withPersistence.whyThisOrder);
check("both programs get a block and three disable moves",
  withPersistence.steps.sever.length === 2 && withPersistence.steps.disable.length === 6,
  `${withPersistence.steps.sever.length} / ${withPersistence.steps.disable.length}`);
check("both mechanisms get a purge step",
  withPersistence.steps.purge.length === 2, String(withPersistence.steps.purge.length));
check("the Run key purge deletes, and says it cannot be undone",
  withPersistence.steps.purge.some((p) => /reg delete/.test(p.command) && p.reversible === false));
check("the task purge disables rather than deletes, and says so",
  withPersistence.steps.purge.some((p) => /schtasks/.test(p.command) && /DISABLE/.test(p.command) && p.reversible === true));

// One program named twice must not produce two blocks.
const twice = neutralizePlan({ persistence: [persistence[0], persistence[0]] });
check("the same program recorded twice is blocked once", twice.steps.sever.length === 1, String(twice.steps.sever.length));
check("but its mechanism is still purged twice, because they are two entries",
  twice.steps.purge.length === 2, String(twice.steps.purge.length));

/* ================================================== credentials change the order */

section("a plaintext export with no autostart puts revocation first");

const jar = "# Netscape HTTP Cookie File\n.example.com\tTRUE\t/\tFALSE\t1750000000\tsid\tsecret\napi.example.org\tFALSE\t/\tTRUE\t1750000000\ttok\tsecret2\n";
const io = { statOf: null, read: (p) => (p.endsWith("cookies.txt") ? jar : "") };
const credOnly = neutralizePlan({ sessionHits: [{ root: "C:\\work", path: "cookies.txt" }], io });
check("revocation comes first when nothing is recorded as restarting",
  credOnly.order[0] === "revoke" && credOnly.order.join(",") === "revoke,purge,sever,disable",
  credOnly.order.join(","));
check("and the reason is that a deleted file cannot be asked again",
  /cannot be reconstructed later|cannot be recomputed/.test(credOnly.whyThisOrder), credOnly.whyThisOrder);
check("both hosts in the jar become revocation steps",
  credOnly.steps.revoke.length === 2 && credOnly.steps.revoke.some((s) => s.target === "example.com"),
  JSON.stringify(credOnly.steps.revoke.map((s) => s.target)));
check("the leading dot on a cookie domain does not survive into the host",
  !credOnly.steps.revoke.some((s) => s.target.startsWith(".")), JSON.stringify(credOnly.steps.revoke.map((s) => s.target)));
check("each revocation names the file it came from",
  credOnly.steps.revoke.every((s) => Array.isArray(s.sources) && s.sources.length === 1));
check("a revocation is not described as reversible",
  credOnly.steps.revoke.every((s) => s.reversible === false));

/* ================================================== what it refuses to guess */

section("what cannot be named is reported, not dropped");

const unresolved = neutralizePlan({ persistence: [{ source: "run-key", subject: "HKCU\\...\\Run\\x", target: "cmd.exe /c start", at: null }] });
check("a command with no path in it lands in unresolved",
  unresolved.unresolved.some((u) => u.layer === "sever"), JSON.stringify(unresolved.unresolved.map((u) => u.layer)));
check("that entry says how to read the real command",
  unresolved.unresolved.some((u) => /reg query/.test(u.how_to_find_out ?? "")), JSON.stringify(unresolved.unresolved));

const admin = neutralizePlan({ persistence: [{ source: "service", subject: "SomeSvc", target: "C:\\Program Files\\x\\a.exe", at: null }] });
check("a program outside user-writable space is flagged rather than blocked",
  admin.unresolved.some((u) => u.layer === "purge") && admin.steps.sever.length === 0,
  JSON.stringify({ sev: admin.steps.sever.length, unres: admin.unresolved.length }));

const unknown = neutralizePlan({ persistence: [{ source: "wer", subject: "a crash report", target: "C:\\x\\y.exe", at: null }] });
check("a mechanism with no generic removal is reported as unresolved",
  unknown.unresolved.some((u) => u.layer === "purge" && /no generic removal/.test(u.why ?? "")),
  JSON.stringify(unknown.unresolved.map((u) => u.why)));

// Measured on this machine: the first run offered a firewall block and three disable moves for
// Defender's own MpCmdRun.exe, because it lives in ProgramData. Following that advice would have
// removed the machine's own protection, and the whole point is that it looked like a correct answer.
const defender = neutralizePlan({ persistence: [{ source: "run-key", subject: "HKLM\\...\\Run\\WinDefend", target: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MpCmdRun.exe", at: null }] });
check("a Defender component gets no move of any kind",
  defender.steps.sever.length === 0 && defender.steps.disable.length === 0,
  JSON.stringify({ sever: defender.steps.sever.length, disable: defender.steps.disable.length }));
check("and the refusal names the product and the outcome it avoids",
  defender.unresolved.some((u) => /Defender/.test(u.why ?? "") && /protection/.test(u.why ?? "")),
  JSON.stringify(defender.unresolved.map((u) => u.why)));
check("the refusal sends the reader to the signature instead",
  defender.unresolved.some((u) => /Get-AuthenticodeSignature/.test(u.how_to_find_out ?? "")));

check("every move that touches a program states what its presence is evidence of",
  [...withPersistence.steps.sever, ...withPersistence.steps.disable].every((m) => /not a verdict/.test(m.on_what_basis ?? "")),
  [...withPersistence.steps.sever, ...withPersistence.steps.disable].map((m) => m.on_what_basis ?? "(none)").join(" | "));

const nothing = neutralizePlan({});
check("an empty plan has all four layers empty and says which",
  nothing.emptyLayers.length === 4 && Object.values(nothing.steps).every((s) => s.length === 0),
  JSON.stringify(nothing.emptyLayers));
check("an empty plan still explains its order",
  typeof nothing.whyThisOrder === "string" && nothing.whyThisOrder.length > 40);

/* ================================================== a real jar on disk */

section("end to end on a jar this suite writes");

// A fixture of a few hundred bytes, written and removed in the same run -- the same shape the other
// suites use, and small enough that the scratch-directory rule is about large files, not about this.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-neutralize-"));
fs.writeFileSync(path.join(tmp, "cookies.txt"), jar);
const real = neutralizePlan({ sessionHits: [{ root: tmp, path: "cookies.txt" }] });
check("the jar is read from disk and both hosts appear",
  real.steps.revoke.length === 2, JSON.stringify(real.steps.revoke.map((s) => s.target)));
check("nothing in the notReadable list, because the format was readable",
  real.notReadable.length === 0, JSON.stringify(real.notReadable));
fs.rmSync(tmp, { recursive: true, force: true });

/* ================================================== summary */

console.log(`\n${fail ? "\u001b[31m" : "\u001b[32m"}${pass} passed, ${fail} failed\u001b[0m`);
if (fail) { for (const f of failures) console.log(`  - ${f}`); process.exit(1); }
