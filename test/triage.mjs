#!/usr/bin/env node
/**
 * Triage suite -- drives lib/triage.mjs: the five artefact surfaces and the correlation over them.
 *
 * Why this needs its own suite:
 *
 *   1. Two of the five surfaces are files that are NOT UTF-8. Scheduled tasks and WER reports are
 *      UTF-16LE with a BOM, and a reader that decodes them as UTF-8 gets text where every character
 *      is followed by a NUL -- so every field pattern fails to match and every task on the machine is
 *      reported as having no command, which reads exactly like a machine with nothing in it. The
 *      fixtures below are written as real UTF-16 bytes, and the assertion that catches the mistake is
 *      that the decoded text contains no NUL at all.
 *
 *   2. The correlation rule has a permissive failure that looks like success. "Several artefacts in
 *      one window" is satisfied by five Prefetch entries from an ordinary hour, so the rule is only
 *      worth having with its control beside it: the same five entries from ONE source must produce no
 *      cluster, and the mixed window must.
 *
 *   3. The module's answer is deliberately smaller than "you are compromised". An autostart pointing
 *      into a user-writable directory is a warning and not a verdict, and the suite asserts the
 *      finding carries that in its own words -- as well as the control, that the same autostart from
 *      Program Files produces nothing at all.
 *
 * Hermeticity: the trees are built in a temp directory that is removed at the end. The bounds are
 * driven through an injected io, because reaching an entry ceiling or a depth limit on a real
 * filesystem would mean building thousands of files.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const {
  TRIAGE_SCHEMA, TRIAGE_NOT_READABLE,
  clustersOf, decodeText, findingsFor, isStandardProgramLocation, looksUserWritable, parseTaskXml, parseWer,
  prefetchSubject, readPrefetch, readScheduledTasks, readStartupFolders, readUserWritableExecutables,
  readWerReports, realTriageIo, timelineOf,
} = await import(pathToFileURL(path.join(root, "lib", "triage.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ====================== fixture ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-triage-"));
const F = (...p) => path.join(base, ...p);
function put(rel, data) {
  const full = F(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data);
  return full;
}
const utf16 = (text) => Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);

// A WER report, the way Windows writes one: UTF-16LE, key=value, one per line.
put("wer/ReportQueue/Report1/Report.wer", utf16(
  "EventType=APPCRASH\r\nAppName=jlhwidsqvfxf.exe\r\nAppPath=C:\\Users\\someone\\AppData\\Local\\Temp\\jlhwidsqvfxf.exe\r\n" +
  "Sig[0].Name=Application Name\r\nSig[0].Value=jlhwidsqvfxf.exe\r\nSig[1].Name=Module Name\r\nSig[1].Value=ntdll.dll\r\n"));
put("wer/ReportArchive/Report2/Report.wer", utf16(
  "EventType=APPCRASH\r\nAppName=firefox.exe\r\nAppPath=C:\\Program Files\\Mozilla Firefox\\firefox.exe\r\n"));

// Prefetch: the name carries the executable, the mtime carries the run.
put("prefetch/JLHWIDSQVFXC.EXE-1A2B3C4D.pf", "pf");
put("prefetch/FIREFOX.EXE-DEADBEEF.pf", "pf");
put("prefetch/notes.txt", "not a prefetch file");

// Startup folders, with the desktop.ini Windows puts in every one of them.
put("startup-user/updater.lnk", "lnk");
put("startup-user/desktop.ini", "ini");
put("startup-all/CompanyAgent.lnk", "lnk");

// Scheduled tasks: XML, UTF-16LE, no file extension.
put("tasks/MyTask", utf16(
  '<?xml version="1.0" encoding="UTF-16"?><Task><Triggers><TimeTrigger><StartBoundary>2026-03-04T05:06:07</StartBoundary></TimeTrigger></Triggers>' +
  '<Principals><Principal><UserId>Administrator</UserId></Principal></Principals><Settings><Enabled>true</Enabled></Settings>' +
  "<Actions><Exec><Command>C:\\Users\\someone\\AppData\\Roaming\\thing\\run.exe</Command><Arguments>--quiet</Arguments></Exec></Actions></Task>"));
put("tasks/sub/Nested", utf16('<?xml version="1.0"?><Task><Settings><Enabled>false</Enabled></Settings><Actions><Exec><Command>C:\\Program Files\\x\\y.exe</Command></Exec></Actions></Task>'));
put("tasks/disabled-no-fields", utf16('<?xml version="1.0"?><Task><Settings/></Task>'));

// Executables in a user-writable location, plus one that is not an executable at all.
put("writable/AppData/Local/thing/run.exe", "MZ");
put("writable/AppData/Roaming/thing/helper.ps1", "script");
put("writable/AppData/Local/thing/readme.txt", "text");
put("writable/AppData/Local/thing/deeper/a/b/c/d/e/too-deep.exe", "MZ");

const io = realTriageIo();

/* ====================== A. decoding ====================== */

section("A. reading a file that is not UTF-8");

const asUtf16 = decodeText(fs.readFileSync(F("tasks/MyTask")));
check("a UTF-16LE file decodes to text with no NUL in it", !asUtf16.includes("\u0000"), JSON.stringify(asUtf16.slice(0, 40)));
check("...and the XML is actually parseable afterwards", asUtf16.includes("<Command>"), JSON.stringify(asUtf16.slice(0, 60)));
// The control: the same bytes read as UTF-8, which is the mistake being guarded against.
const asUtf8 = fs.readFileSync(F("tasks/MyTask")).toString("utf8");
check("the same bytes read as UTF-8 would be full of NULs, which is the defect",
  asUtf8.includes("\u0000"), JSON.stringify(asUtf8.slice(0, 40)));
// The BOM is the only signal that the bytes are big-endian; without it there is nothing to detect
// and the reader is right to treat the input as UTF-8. So the fixture supplies one.
const beBytes = Buffer.from("ab", "utf16le");
beBytes.swap16();
check("a UTF-16BE file is decoded rather than mangled",
  decodeText(Buffer.concat([Buffer.from([0xfe, 0xff]), beBytes])) === "ab");
check("...and without a BOM those same bytes are read as UTF-8, which is the honest answer",
  decodeText(beBytes) !== "ab");
check("a plain UTF-8 file is left alone", decodeText(Buffer.from("plain", "utf8")) === "plain");
check("an empty buffer is an empty string, not a crash", decodeText(Buffer.alloc(0)) === "" && decodeText(null) === "");

/* ====================== B. WER ====================== */

section("B. crash reports");

const werText = decodeText(fs.readFileSync(F("wer/ReportQueue/Report1/Report.wer")));
const parsedWere = parseWer(werText);
check("key=value lines are read", parsedWere.fields.AppName === "jlhwidsqvfxf.exe", JSON.stringify(parsedWere.fields));
check("the signature pairs are folded", parsedWere.signature_values.includes("jlhwidsqvfxf.exe"), JSON.stringify(parsedWere.signature_values));
check("a line with no equals sign is skipped and does not crash the reader", parseWer("no equals here\nAppName=x").fields.AppName === "x");
check("the first occurrence of a repeated key wins", parseWer("AppName=first\nAppName=second").fields.AppName === "first");

const werEntries = readWerReports(io, F("wer"));
check("both queues are walked", werEntries.length === 2, JSON.stringify(werEntries.map((e) => e.subject)));
check("the subject is the executable", werEntries.some((e) => e.subject === "jlhwidsqvfxf.exe"));
check("the path travels with it", werEntries.find((e) => e.subject === "jlhwidsqvfxf.exe")?.path?.endsWith("jlhwidsqvfxf.exe") === true);
check("each entry is dated, which is what a timeline needs", werEntries.every((e) => typeof e.at === "string"));
check("a missing directory is an empty answer, not a throw", readWerReports(io, F("no-such-dir")).length === 0);

/* ====================== C. Prefetch ====================== */

section("C. what ran");

check("a hashed name yields the executable", prefetchSubject("JLHWIDSQVFXC.EXE-1A2B3C4D.pf") === "JLHWIDSQVFXC.EXE");
check("an unhashed name yields itself", prefetchSubject("FIREFOX.EXE.pf") === "FIREFOX.EXE");
check("a dash in the name is not mistaken for the hash", prefetchSubject("MY-TOOL.EXE-ABCDEF12.pf") === "MY-TOOL.EXE");
check("a lowercase hash works", prefetchSubject("x.exe-deadbeef.pf") === "x.exe");

const prefetchEntries = readPrefetch(io, F("prefetch"));
check("only .pf files are taken", prefetchEntries.length === 2, JSON.stringify(prefetchEntries.map((e) => e.subject)));
check("the subject is the executable, not the file", prefetchEntries.some((e) => e.subject === "JLHWIDSQVFXC.EXE"));
check("each is dated from the file", prefetchEntries.every((e) => typeof e.at === "string"));

/* ====================== D. autostart ====================== */

section("D. what starts by itself");

const startupEntries = readStartupFolders(io, [F("startup-user"), F("startup-all"), F("no-such")]);
check("both startup folders are read", startupEntries.length === 2, JSON.stringify(startupEntries.map((e) => e.subject)));
check("desktop.ini is not an autostart entry", !startupEntries.some((e) => /desktop\.ini/i.test(e.subject)));
check("a folder that does not exist contributes nothing", readStartupFolders(io, [F("no-such")]).length === 0);

const taskEntries = readScheduledTasks(io, F("tasks"));
check("tasks are found, including in subfolders", taskEntries.length === 3, JSON.stringify(taskEntries.map((e) => e.subject)));
const mine = taskEntries.find((e) => e.subject === "MyTask");
check("a task's command is read out of UTF-16 XML", mine?.path?.endsWith("run.exe") === true, JSON.stringify(mine));
check("its arguments travel too", mine?.arguments?.[0] === "--quiet", JSON.stringify(mine?.arguments));
// A StartBoundary carries no timezone, so Date.parse reads it as LOCAL time -- and the entry is
// reported in UTC. The expectation is computed through the same conversion rather than written as a
// date literal, because a literal would only hold in the timezone the test was written in.
check("a task with a start boundary is dated by it",
  mine?.at === new Date("2026-03-04T05:06:07").toISOString(),
  `${mine?.at} vs ${new Date("2026-03-04T05:06:07").toISOString()}`);
check("a task with nothing in it is still listed rather than dropped",
  taskEntries.some((e) => e.subject === "disabled-no-fields" && e.path === null));
check("a disabled task is reported as disabled", taskEntries.find((e) => e.subject === "sub/Nested")?.detail?.includes("enabled=false") === true);
check("the parser says what it is: a pattern over the fields, not a parser",
  parseTaskXml("<Task><Settings><Enabled>true</Enabled></Settings></Task>").enabled === "true"
  && parseTaskXml("no xml at all").enabled === null);

/* ====================== E. user-writable executables ====================== */

section("E. executables where anything can be written");

const writable = readUserWritableExecutables(io, [F("writable/AppData")], { maxDepth: 4 });
check("executables and scripts are collected", writable.length === 2, JSON.stringify(writable.map((e) => e.subject)));
check("a text file is not", !writable.some((e) => e.subject === "readme.txt"));
check("a file past the depth limit is not reached", !writable.some((e) => /too-deep/.test(e.subject)));
check("and one AT the limit is, which is the control for the bound",
  readUserWritableExecutables(io, [F("writable/AppData")], { maxDepth: 9 }).some((e) => /too-deep/.test(e.subject)));

// Truncation, per surface and against a ceiling the fixture can actually reach. A reader that
// stopped early and said nothing would report "4000 executables" for a machine that has more, which
// reads as a count rather than as a limit -- the same defect the tree-match depth bound had.
{
  const budget = { truncated: false };
  readUserWritableExecutables(io, [F("writable/AppData")], { maxDepth: 4, maxFiles: 1, budget });
  check("a sweep that hit its ceiling says so", budget.truncated === true);
  const roomy = { truncated: false };
  readUserWritableExecutables(io, [F("writable/AppData")], { maxDepth: 4, maxFiles: 50, budget: roomy });
  check("a sweep that finished does not claim truncation", roomy.truncated === false);

  const pf = { truncated: false };
  readPrefetch(io, F("prefetch"), { maxFiles: 1, budget: pf });
  check("a prefetch listing that hit its ceiling says so", pf.truncated === true);
  const pf2 = { truncated: false };
  readPrefetch(io, F("prefetch"), { maxFiles: 99, budget: pf2 });
  check("and a complete one does not", pf2.truncated === false);

  const wer = { truncated: false };
  readWerReports(io, F("wer"), { maxFiles: 1, budget: wer });
  check("a crash-report walk that hit its ceiling says so", wer.truncated === true);
}

/* ====================== F. the timeline ====================== */

section("F. aligning them in time");

const all = [...werEntries, ...prefetchEntries, ...startupEntries, ...taskEntries];
const undated = { at: null, source: "prefetch", subject: "unknown" };
const line = timelineOf([...all, undated]);
check("the timeline is sorted oldest first",
  line.slice(0, -1).every((e, i) => !e.at || !line[i + 1].at || e.at <= line[i + 1].at), JSON.stringify(line.map((e) => e.at)));
check("an entry with no time is kept at the end rather than dropped",
  line[line.length - 1] === undated, String(line[line.length - 1]?.subject));
check("an empty input is an empty timeline", timelineOf([]).length === 0 && timelineOf(null).length === 0);

/* ====================== G. the correlation ====================== */

section("G. several kinds of artefact in one window");

const hour = 60 * 60 * 1000;
const t = (mins, source, subject) => ({ at: new Date(Date.UTC(2026, 2, 4, 12, mins)).toISOString(), source, subject });

const mixed = clustersOf([t(0, "prefetch", "a"), t(5, "task", "b"), t(9, "wer", "c")]);
check("a window spanning several sources is reported", mixed.length === 1 && mixed[0].sources.length === 3, JSON.stringify(mixed));
check("it names the window", mixed[0].from < mixed[0].to && mixed[0].entries === 3, JSON.stringify(mixed[0]));

// The control that gives the rule its teeth: five entries, one source, no cluster.
const oneSource = clustersOf([t(0, "prefetch", "a"), t(3, "prefetch", "b"), t(6, "prefetch", "c"), t(9, "prefetch", "d"), t(11, "prefetch", "e")]);
check("five entries from ONE source are not a cluster", oneSource.length === 0, JSON.stringify(oneSource));
check("...which is what makes the mixed one mean something", mixed.length === 1);

// Three entries per window, because the default minimum is three: a two-entry window would be
// dropped by the rule rather than by the interval, and the test would then be asserting the wrong
// thing about why it split.
const farApart = clustersOf([t(0, "prefetch", "a"), t(5, "task", "b"), t(9, "wer", "c"), t(300, "wer", "d"), t(305, "task", "e"), t(309, "startup", "f")]);
check("a window that runs past the interval becomes two", farApart.length === 2, JSON.stringify(farApart));
check("a cluster smaller than the minimum is not reported",
  clustersOf([t(0, "prefetch", "a"), t(1, "task", "b")], { minEntries: 5 }).length === 0);
check("entries with no time cannot form a cluster", clustersOf([undated, undated, undated]).length === 0);

/* ====================== H. the judgements ====================== */

section("H. what it says, and what it does not");

check("a user-writable location is recognised", looksUserWritable("C:\\Users\\x\\AppData\\Local\\T\\a.exe") === true);
check("Program Files is not one", looksUserWritable("C:\\Program Files\\a\\b.exe") === false);
check("a directory that merely contains the word is not one", looksUserWritable("C:\\Tools\\AppDataTool\\x.exe") === false);
check("Program Files is a standard location", isStandardProgramLocation("C:\\Program Files\\Mozilla Firefox\\firefox.exe") === true);
check("so is Windows itself", isStandardProgramLocation("C:\\Windows\\System32\\app.exe") === true);
check("and Program Files (x86)", isStandardProgramLocation("C:\\Program Files (x86)\\x\\y.exe") === true);
check("a user-writable path is NOT one, which is the direction that matters", isStandardProgramLocation("C:\\Users\\x\\AppData\\Local\\T\\a.exe") === false);

const findings = findingsFor(all);
const ids = findings.map((f) => f.id);
check("an autostart into a user-writable place is a warning",
  ids.includes("triage-autostart-user-writable"), JSON.stringify(ids));
const warn = findings.find((f) => f.id === "triage-autostart-user-writable");
check("its severity is warn, not critical", warn.severity === "warn", warn.severity);
check("it states what it does NOT mean",
  /not a verdict|does not|whether the file is malicious/i.test(warn.detail), warn.detail);
check("every finding carries its own boundary", findings.every((f) => typeof f.does_not_cover === "string" && f.does_not_cover.length > 30));

// The control: the same shapes, in the places they are supposed to be.
const clean = findingsFor([
  { at: "2026-03-04T00:00:00Z", source: "task", subject: "t", path: "C:\\Program Files\\x\\y.exe", report: "C:\\Windows\\System32\\Tasks\\t" },
  { at: "2026-03-04T00:00:00Z", source: "wer", subject: "z", path: "C:\\Program Files\\z\\z.exe", report: null },
]);
check("a task pointing into Program Files produces no warning",
  !clean.map((f) => f.id).includes("triage-autostart-user-writable"), JSON.stringify(clean.map((f) => f.id)));
check("a crash inside Program Files is not reported as one outside",
  !clean.map((f) => f.id).includes("triage-crash-outside-program-files"), JSON.stringify(clean.map((f) => f.id)));
check("an empty input produces no findings at all", findingsFor([]).length === 0);

/* ====================== I. what it cannot read ====================== */

section("I. the surfaces it declines to guess about");

// The list SHRANK, and these assertions were rewritten to record that rather than to accommodate it.
// The Run keys, the service table and Defender's configuration were on it and are now read; what is
// left is what needs a parser against a copy of a hive, and the content of a store the engine reads.
// The two checks below therefore run in both directions: the remainder has to be there, and the three
// that were removed have to stay removed -- so putting one back is a failing check, not a silent edit.
check("the list is not empty", TRIAGE_NOT_READABLE.length >= 2, String(TRIAGE_NOT_READABLE.length));
check("every entry names the surface, why, and the command that answers it",
  TRIAGE_NOT_READABLE.every((e) => e.surface && e.why && e.answerable_by));
check("what remains is the parser work and the store content",
  TRIAGE_NOT_READABLE.some((e) => /Amcache/i.test(e.surface)) && TRIAGE_NOT_READABLE.some((e) => /CONTENT/i.test(e.surface)),
  TRIAGE_NOT_READABLE.map((e) => e.surface).join(" | "));
check("the registry surfaces that ARE read are no longer listed as unreachable",
  !TRIAGE_NOT_READABLE.some((e) => /Run and RunOnce|service table/i.test(e.surface)),
  TRIAGE_NOT_READABLE.map((e) => e.surface).join(" | "));
check("and Defender's history is listed for its CONTENT, with the command that answers it",
  TRIAGE_NOT_READABLE.some((e) => /Defender/.test(e.surface) && /Get-MpThreatDetection/.test(e.answerable_by)));
check("the schema is versioned", /^aikawamei-triage\/\d+$/.test(TRIAGE_SCHEMA), TRIAGE_SCHEMA);

/* ====================== J. the tool ====================== */

section("J. the tool over a fixture machine");

// A second layout, because the tool builds its own paths from the roots it is given:
// `<windows>/Prefetch`, `<windows>/System32/Tasks`, `<local>/Microsoft/Windows/WER`, and the Startup
// folders under the application-data directories. Pointing it at these is how the tool is driven
// without reading the real machine.
put("win/Prefetch/JLHWIDSQVFXC.EXE-1A2B3C4D.pf", "pf");
put("win/System32/Tasks/MyTask", utf16(
  '<?xml version="1.0" encoding="UTF-16"?><Task><Settings><Enabled>true</Enabled></Settings>' +
  "<Actions><Exec><Command>C:\\Users\\someone\\AppData\\Local\\T\\run.exe</Command></Exec></Actions></Task>"));
put("lad/Microsoft/Windows/WER/ReportQueue/R/Report.wer", utf16("AppName=thing.exe\r\nAppPath=C:\\Users\\someone\\AppData\\Local\\T\\thing.exe\r\n"));
put("ad/Microsoft/Windows/Start Menu/Programs/Startup/startme.lnk", "lnk");
put("pd/Microsoft/Windows/Start Menu/Programs/StartUp/all-users.lnk", "lnk");
put("lad/AppData/Local/t/thing.exe", "MZ");

const tools = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const triageTool = tools.TOOLS.find((t) => t.name === "aikawamei_triage");
const fixtureRoots = {
  windows_root: F("win"),
  app_data: F("ad"),
  local_app_data: F("lad"),
  program_data: F("pd"),
  user_root: F("user"),
};

check("the tool exists and is registered", !!triageTool);
const run = await triageTool.execute({ ...fixtureRoots, timeline_limit: 40 });
// The five file surfaces come from the fixture; the three registry surfaces do not, because a fixture
// cannot stand in for a registry. So this asserts that every surface WAS read and how it says so --
// the path surfaces carry a path, the registry ones carry a kind -- and deliberately does not assert
// any count, because the counts belong to the machine and a suite that depends on them passes only on
// the machine it was written on. The parsing of those three is covered by test/triage-registry.mjs,
// which drives them through an injected query and therefore knows exactly what it is reading.
const pathSurfaces = run.surfaces.filter((s) => s.kind !== "registry");
const regSurfaces = run.surfaces.filter((s) => s.kind === "registry");
check("every file surface the layout supports is read",
  pathSurfaces.length === 5 && pathSurfaces.every((s) => s.read === true), JSON.stringify(pathSurfaces));
check("the three registry surfaces are read too, and say what they are",
  regSurfaces.length === 3 && regSurfaces.every((s) => s.read === true && s.name),
  JSON.stringify(regSurfaces.map((s) => s.name)));
check("a surface that could not be read says why",
  run.surfaces.every((s) => s.read || typeof s.reason === "string"), JSON.stringify(run.surfaces));
check("the artefact count is what the surfaces contributed",
  run.timeline_total > 0 && run.timeline_total === run.surfaces.reduce((n, s) => n + (s.entries ?? 0), 0),
  JSON.stringify({ total: run.timeline_total, surfaces: run.surfaces.map((s) => s.entries) }));
check("the findings conform to the catalog", run.checks?.conformant === true, JSON.stringify(run.checks?.unknown));
check("the ids emitted are the catalogued ones",
  run.findings.length > 0 && run.findings.every((f) => /^triage-/.test(f.id)), JSON.stringify(run.findings.map((f) => f.id)));
check("the surfaces it cannot read travel with the answer, and they are the two that remain",
  run.not_readable.length === TRIAGE_NOT_READABLE.length
  && run.not_readable.some((e) => /Amcache/i.test(e.surface))
  && run.not_readable.some((e) => /CONTENT/i.test(e.surface)),
  JSON.stringify(run.not_readable.map((e) => e.surface)));
check("the scope is reported, and says it is not verified",
  run.scope?.verified === false && Array.isArray(run.refused), JSON.stringify(run.scope));

// The timeline bound, as a pair: a small limit truncates and says so; a large one does not.
const bounded = await triageTool.execute({ ...fixtureRoots, timeline_limit: 1 });
check("a bounded timeline says it was truncated",
  bounded.timeline_returned === 1 && bounded.timeline_truncated === true,
  JSON.stringify({ returned: bounded.timeline_returned, truncated: bounded.timeline_truncated }));
check("the total is still reported beside it, so the bound reads as a bound",
  bounded.timeline_total === run.timeline_total);
check("a timeline that fits does not claim truncation",
  (await triageTool.execute({ ...fixtureRoots, timeline_limit: 500 })).timeline_truncated === false);

// The scope guard applies to the system paths too, and the refusal is visible rather than silent.
const narrowed = await triageTool.execute({ ...fixtureRoots, scope: [F("win")] });
check("a narrow declaration refuses the surfaces outside it",
  narrowed.refused.length >= 2 && narrowed.surfaces.some((s) => s.read === false && /scope/.test(s.reason ?? "")),
  JSON.stringify({ refused: narrowed.refused.length, read: narrowed.surfaces.map((s) => s.read) }));
check("...and still reads the one inside it",
  narrowed.surfaces.some((s) => s.name === "prefetch" && s.read === true));

// The correlation knobs reach the report.
const wide = await triageTool.execute({ ...fixtureRoots, window_minutes: 100000, min_cluster: 2 });
check("a window wide enough to hold everything produces a cluster", wide.clusters.length >= 1, String(wide.clusters.length));
check("and every reported window spans more than one source",
  wide.clusters.every((c) => c.sources.length > 1), JSON.stringify(wide.clusters));

// The record, in the same two shapes the sessions tool has.
process.env.AIKAWAMEI_VAULT_PASSPHRASE = "a passphrase for the suite";
const triageVaultDir = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-triage-vault-"));
const triageChain = path.join(triageVaultDir, "chain.jsonl");
const recorded = await triageTool.execute({ ...fixtureRoots, vault: triageChain });
const rawTriage = fs.readFileSync(triageChain, "utf8");
check("a triage run can leave a record", recorded.vault?.length === 1, JSON.stringify(recorded.vault));
check("the record counts what it saw", /surface\(s\) read/.test(rawTriage), rawTriage.slice(0, 140));
check("the cleartext names no path from the scan",
  !rawTriage.includes("Report.wer") && !rawTriage.includes("MyTask") && !rawTriage.includes("startme"), rawTriage.slice(0, 180));
check("and the sealed payload is readable with the passphrase",
  JSON.stringify((await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href))
    .openValue(process.env.AIKAWAMEI_VAULT_PASSPHRASE, JSON.parse(rawTriage.trim()).sealed)).includes("wer"));
check("with no vault named, nothing is written",
  (await triageTool.execute(fixtureRoots)).vault === undefined);
delete process.env.AIKAWAMEI_VAULT_PASSPHRASE;
try { fs.rmSync(triageVaultDir, { recursive: true, force: true }); } catch {}

/* ====================== summary ====================== */

try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mtemporary fixtures cleaned up\u001b[0m"); } catch {}

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
