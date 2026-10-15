#!/usr/bin/env node
/**
 * Triage registry suite -- drives the three surfaces that are not files: the Run keys, the automatic
 * services, and Defender's own configuration.
 *
 * Why a separate suite rather than more assertions in the triage one
 * ----------------------------------------------------------------
 *   1. THE TRUTH HERE COMES FROM A PROGRAM, NOT FROM A FILE. Everything else this project reads can be
 *      faked by putting a file in a temporary directory. `reg query` cannot, so the query is injected
 *      and every assertion below feeds it text that has the REAL shape -- two lines per value, which
 *      is the shape that two rounds of this work got wrong: a pattern expecting the key path and the
 *      value on one line returned nothing for every service, and a parser that returns nothing on a
 *      machine full of autostart entries reads as a clean machine.
 *
 *   2. NOTHING HERE TOUCHES THE REAL REGISTRY. A suite that depends on the machine it runs on passes
 *      on the machine it was written on, which is the same defect as a hardcoded path.
 *
 *   3. THE ENVIRONMENT VARIABLES ARE THE WHOLE DIFFERENCE between a report and noise. Measured on
 *      this machine before the expansion existed: 101 of 119 automatic services looked like they ran
 *      from somewhere unusual, and every one of them was written as %SystemRoot%\System32\... .
 *
 * Division of labour: the triage suite owns the file surfaces; this one owns the three that are read
 *   through a query, and the judgement that the environment variables have to be expanded before it.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const triage = await import(pathToFileURL(path.join(root, "lib", "triage.mjs")).href);
const checks = await import(pathToFileURL(path.join(root, "lib", "checks.mjs")).href);
const {
  REGISTRY_SURFACES, parseRegQuery, readRunKeys, readServiceAutostarts, readDefenderState,
  expandEnvPath, findingsFor, looksUserWritable, isStandardProgramLocation,
} = triage;
const { CHECK_CATALOG } = checks;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/** An io whose query returns whatever the test hands it, keyed by the key asked about. */
function fakeIo(answers, { files = {}, dirs = {} } = {}) {
  return {
    exists: (p) => Object.prototype.hasOwnProperty.call(files, p) || Object.prototype.hasOwnProperty.call(dirs, p),
    statOf: (p) => (files[p] ? { size: files[p].bytes ?? 1, mtime: files[p].mtime ?? new Date("2026-01-01T00:00:00Z") } : null),
    listDir: (p) => (dirs[p] ?? []).map((n) => ({ name: n, isDirectory: () => !n.includes(".") })),
    readBytes: (p) => (files[p] ? Buffer.from("x") : null),
    runQuery: (key, opts = {}) => {
      const k = opts.value ? `${key} /v ${opts.value}` : key;
      const a = answers[k] ?? answers[key];
      if (a === undefined) return { ok: false, reason: "the registry tool could not be run" };
      return a;
    },
  };
}

/* ================================================== the shape of the real output */

section("the parser, against the shape reg query really prints");

const REAL_HKCU = [
  "",
  "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "    ctfmon    REG_SZ    C:\\Windows\\system32\\ctfmon.exe",
  "    LGHUB    REG_SZ    \"C:\\Program Files\\LGHUB\\system_tray\\lghub_system_tray.exe\" --minimized",
  "",
].join("\r\n");

const parsed = parseRegQuery(REAL_HKCU);
check("a real HKCU Run block parses into its values", parsed.length === 2, JSON.stringify(parsed.length));
check("the key path line is not mistaken for a value",
  parsed.every((v) => v.name !== "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
check("the name, the type and the value are separated",
  parsed[0].name === "ctfmon" && parsed[0].type === "REG_SZ" && parsed[0].value === "C:\\Windows\\system32\\ctfmon.exe",
  JSON.stringify(parsed[0]));
check("quotes and trailing arguments stay in the value",
  parsed[1].value === "\"C:\\Program Files\\LGHUB\\system_tray\\lghub_system_tray.exe\" --minimized", parsed[1].value);

/* ================================================== run keys */

section("the Run keys, read and not-read as different outcomes");

const runIo = fakeIo({
  [REGISTRY_SURFACES.run[0].key]: { ok: true, text: REAL_HKCU },
  [REGISTRY_SURFACES.run[1].key]: { ok: true, text: "" },
  [REGISTRY_SURFACES.run[2].key]: { ok: true, text: "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    SecurityHealth    REG_EXPAND_SZ    %windir%\\system32\\SecurityHealthSystray.exe\r\n" },
  [REGISTRY_SURFACES.run[3].key]: { ok: true, text: "" },
  [REGISTRY_SURFACES.run[4].key]: { ok: true, text: "" },
  [REGISTRY_SURFACES.run[5].key]: { ok: true, text: "" },
});
const runEntries = readRunKeys(runIo);
check("three autostart values across the six keys", runEntries.length === 3, String(runEntries.length));
check("every entry carries the command it would run",
  runEntries.every((e) => typeof e.command === "string" && e.command.length > 0));
check("an empty key contributes nothing and is not reported as unread",
  runEntries.filter((e) => e.unread).length === 0, String(runEntries.filter((e) => e.unread).length));
check("a registry value carries no timestamp rather than an invented one",
  runEntries.every((e) => e.at === null));

const brokenIo = fakeIo({});
const brokenRun = readRunKeys(brokenIo);
check("a query that cannot run is reported as not read, not as nothing found",
  brokenRun.length === REGISTRY_SURFACES.run.length && brokenRun.every((e) => e.unread === true),
  JSON.stringify(brokenRun.map((e) => e.detail).slice(0, 2)));

const noQuery = { exists: () => false, statOf: () => null, listDir: () => [], readBytes: () => null };
check("an io with no query at all degrades the same way, and says why",
  readRunKeys(noQuery).every((e) => e.unread === true && /no registry query/.test(e.detail)));

/* ================================================== services */

section("the service table: Start 2 only, joined with the command each one runs");

const SERVICES = "HKLM\\SYSTEM\\CurrentControlSet\\Services";
const START_TEXT = [
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler",
  "    Start    REG_DWORD    0x2",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ManualThing",
  "    Start    REG_DWORD    0x3",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DisabledThing",
  "    Start    REG_DWORD    0x4",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecondAuto",
  "    Start    REG_DWORD    0x2",
].join("\r\n");
const IMAGE_TEXT = [
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler",
  "    ImagePath    REG_EXPAND_SZ    %SystemRoot%\\System32\\spoolsv.exe",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\ManualThing",
  "    ImagePath    REG_EXPAND_SZ    C:\\Tools\\manual.exe",
  "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SecondAuto",
  "    ImagePath    REG_SZ    C:\\Users\\someone\\AppData\\Local\\Temp\\auto.exe",
].join("\r\n");

const svc = readServiceAutostarts(fakeIo({
  [`${SERVICES} /v Start`]: { ok: true, text: START_TEXT },
  [`${SERVICES} /v ImagePath`]: { ok: true, text: IMAGE_TEXT },
}));
check("only the automatic services are reported", svc.length === 2, svc.map((e) => e.subject).join(","));
check("manual and disabled services are left out", !svc.some((e) => /ManualThing|DisabledThing/.test(e.subject)));
check("each automatic service carries the command it runs",
  svc.find((e) => e.subject === "Spooler")?.command === "%SystemRoot%\\System32\\spoolsv.exe",
  JSON.stringify(svc.map((e) => [e.subject, e.command])));
check("a service whose ImagePath was not in the output still appears, with a null command",
  svc.every((e) => "command" in e));
check("the pattern that expects one line per service is not what is used here (two-line shape)",
  svc.length === 2);

const capped = readServiceAutostarts(fakeIo({
  [`${SERVICES} /v Start`]: { ok: true, text: START_TEXT },
  [`${SERVICES} /v ImagePath`]: { ok: true, text: IMAGE_TEXT },
}), { maxServices: 1 });
check("the service ceiling is respected", capped.length === 1, String(capped.length));

const svcUnread = readServiceAutostarts(fakeIo({}));
check("an unreadable service table is one unread entry, not an empty list",
  svcUnread.length === 1 && svcUnread[0].unread === true, JSON.stringify(svcUnread));

/* ================================================== defender */

section("Defender: the policy key whole, the state key filtered, the history listed but not opened");

const POLICY = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender";
const STATE = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender";
const SUPPORT = "C:\\ProgramData\\Microsoft\\Windows Defender\\Support";

const policyText = [
  "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
  "    DisableAntiSpyware    REG_DWORD    0x1",
].join("\r\n");
const stateText = [
  "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender",
  "    ProductStatus    REG_DWORD    0x0",
  "    PassiveMode    REG_DWORD    0x0",
  "    ProductAppDataPath    REG_SZ    C:\\ProgramData\\Microsoft\\Windows Defender",
  "    RandomNoise1    REG_SZ    something true and uninteresting",
  "    RandomNoise2    REG_SZ    something true and uninteresting",
].join("\r\n");

const def = readDefenderState(fakeIo({
  [POLICY]: { ok: true, text: policyText },
  [STATE]: { ok: true, text: stateText },
}, {
  dirs: { [SUPPORT]: ["MPDetection-20260916-184910.log", "MPLog-20260618-124856.log"] },
  files: {
    [`${SUPPORT}\\MPDetection-20260916-184910.log`]: { bytes: 25030, mtime: new Date("2026-09-16T18:49:10Z") },
    [`${SUPPORT}\\MPLog-20260618-124856.log`]: { bytes: 451788, mtime: new Date("2026-06-18T12:48:56Z") },
  },
}), { historyRoots: [SUPPORT] });

const defSubjects = def.map((e) => e.subject);
check("the policy key is reported whole", defSubjects.some((s) => /DisableAntiSpyware/.test(s)), defSubjects.join(" | "));
check("the state key is filtered to the values that bear on the guard",
  defSubjects.some((s) => /ProductStatus/.test(s)) && !defSubjects.some((s) => /RandomNoise/.test(s)),
  defSubjects.join(" | "));
check("the history is listed by name and size", def.some((e) => /MPDetection-/.test(e.subject) && /25030 bytes/.test(e.detail)));
check("and the entry says where its content belongs",
  def.some((e) => /content tool/.test(e.detail)), def.map((e) => e.detail).join(" | ").slice(0, 160));
check("a file in the history does not count as one of the filtered state values",
  def.filter((e) => /MPLog/.test(e.subject)).every((e) => e.source === "defender" && e.at !== null));
// Behaviour rather than text: the io is built so that reading a byte throws. If readDefenderState
// opens anything, this fails because it tried -- which is a stronger statement than a string search,
// and it does not depend on where a word happens to appear in the file.
{
  const throwingIo = {
    exists: (p) => p === SUPPORT,
    statOf: () => ({ size: 10, mtime: new Date("2026-01-01T00:00:00Z") }),
    listDir: () => [{ name: "MPLog-x.log", isDirectory: () => false }],
    readBytes: () => { throw new Error("readDefenderState opened a file"); },
    runQuery: () => ({ ok: false, reason: "not asked in this case" }),
  };
  let threw = false;
  try { readDefenderState(throwingIo, { historyRoots: [SUPPORT] }); } catch { threw = true; }
  check("the history is read by name only: opening a byte makes the reader throw", threw === false);
}

/* ================================================== environment expansion */

section("environment variables, expanded before any judgement about a path");

check("a known variable expands", expandEnvPath("%SystemRoot%\\System32\\svchost.exe") === "C:\\Windows\\System32\\svchost.exe",
  expandEnvPath("%SystemRoot%\\System32\\svchost.exe"));
check("the expansion is case-insensitive", expandEnvPath("%systemroot%\\x.exe") === "C:\\Windows\\x.exe");
check("an unknown variable is left as written rather than blanked",
  expandEnvPath("%NOPE_NOT_SET%\\x.exe") === "%NOPE_NOT_SET%\\x.exe");
check("a path with no variable is returned unchanged", expandEnvPath("C:\\Windows\\x.exe") === "C:\\Windows\\x.exe");

check("the filter that matters: a %SystemRoot% command is a standard location after expansion",
  isStandardProgramLocation(expandEnvPath("%SystemRoot%\\System32\\svchost.exe")));
check("and it is NOT one before expansion, which is the defect this fixes",
  !isStandardProgramLocation("%SystemRoot%\\System32\\svchost.exe"));

/* ================================================== the judgements */

section("the judgements, each as a pair");

const verdicts = (entries) => findingsFor(entries).map((f) => f.id);
const make = (source, command) => ({ at: null, source, subject: "test", path: "test", command, report: "test", signature: [] });

check("a Run key pointing into a user-writable directory is reported",
  verdicts([make("run-key", "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe")]).includes("triage-autostart-user-writable"));
check("the same Run key pointing into Program Files is not",
  !verdicts([make("run-key", "C:\\Program Files\\App\\a.exe")]).includes("triage-autostart-user-writable"));
check("a service pointing into %APPDATA% is reported",
  verdicts([make("service", expandEnvPath("%APPDATA%\\evil.exe"))]).includes("triage-autostart-user-writable"));
check("a service written as %SystemRoot%\\... is not, once expanded",
  !verdicts([{ ...make("service", "%SystemRoot%\\System32\\svchost.exe") }]).includes("triage-autostart-user-writable"),
  verdicts([make("service", "%SystemRoot%\\System32\\svchost.exe")]).join(","));

const guardOn = { at: null, source: "defender", subject: "Defender state: DisableAntiSpyware", path: "x", command: "0x0", report: "x", signature: [] };
const guardOff = { ...guardOn, command: "0x1" };
const tamperOff = { ...guardOn, subject: "Defender state: TamperProtection", command: "0x0" };
check("a guard that is switched off is reported as critical",
  verdicts([guardOff]).includes("triage-guard-disabled"));
check("and one that is on is not",
  !verdicts([guardOn]).includes("triage-guard-disabled"));
check("tamper protection at zero counts as off",
  verdicts([tamperOff]).includes("triage-guard-disabled"));
check("the finding states that it does not say who changed it",
  findingsFor([guardOff]).find((f) => f.id === "triage-guard-disabled").does_not_cover.includes("Who changed it"));

check("the correlation finding needs more than one mechanism",
  !verdicts([make("run-key", "C:\\x")]).includes("triage-correlated-window"));
check("and appears when two mechanisms agree inside the window",
  verdicts([
    { ...make("run-key", "C:\\x"), at: "2026-01-01T10:00:00Z" },
    { ...make("service", "C:\\y"), at: "2026-01-01T10:10:00Z" },
    { ...make("wer", "C:\\z"), at: "2026-01-01T10:20:00Z" },
  ]).includes("triage-correlated-window"));

/* ================================================== everything lands in the catalog */

section("every id the new surfaces can emit is a catalog entry");

const emittedHere = ["triage-autostart-user-writable", "triage-guard-disabled", "triage-correlated-window"];
check("the ids this suite exercises are catalogued",
  emittedHere.every((id) => CHECK_CATALOG.some((c) => c.id === id)), emittedHere.join(","));
check("the guard finding is declared critical, matching what the code emits",
  CHECK_CATALOG.find((c) => c.id === "triage-guard-disabled").severities.includes("critical"));

/* ================================================== only reading, structurally */

section("the query is the only program, and it only reads");

const src = fs.readFileSync(path.join(root, "lib", "triage.mjs"), "utf8");
check("the module runs exactly one program", (src.match(/execFileSync\(/g) ?? []).length === 1,
  String((src.match(/execFileSync\(/g) ?? []).length));
check("and it is the system's registry tool", /"reg\.exe"/.test(src));
check("the command is built as an argv array, not a shell string",
  /execFileSync\("reg\.exe", argv,/.test(src));
check("no registry-writing verb appears anywhere in the module",
  !/reg(\.exe)?",\s*\[[^\]]*"(add|delete|import|copy|save|restore|load|unload)"/.test(src));
check("no shell is involved", !/\b(shell:\s*true|cmd\.exe|\/c\s)/.test(src));

/* ================================================== summary */

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
