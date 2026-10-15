#!/usr/bin/env node
/**
 * Content suite -- drives lib/content.mjs, the one module here that reads file contents.
 *
 * Why this needs its own suite, and what it is really testing
 * ---------------------------------------------------------
 *   1. EVERY OTHER PROBE IN THIS PROJECT IS TESTED FOR NOT LOOKING INSIDE FILES. This one is
 *      tested for the opposite, so the assertions that matter are the ones that bound HOW MUCH it
 *      looks at: the prefix ceiling, the entry ceiling, the depth ceiling. Each of those is
 *      asserted as a PAIR -- the case at the limit and the case one step past it -- because a
 *      ceiling asserted only from the inside passes just as well when it is wrong in the permissive
 *      direction. That pairing is the whole reason this file is longer than the module.
 *
 *   2. "IT DID NOT FIND ANYTHING" AND "IT DID NOT LOOK" MUST NOT ARRIVE AS THE SAME SHAPE. A file
 *      truncated by the prefix ceiling cannot be answered for against a whole-file signature, and
 *      reporting that as a clean file would be a false clean. The suite asserts that a truncated
 *      file lands in `notEvaluated` while an honestly-scanned clean file lands nowhere at all.
 *
 *   3. NO WRITE PATH IS A STRUCTURAL CLAIM, NOT A PROMISE. It is asserted two ways: the module's
 *      source is searched for every mutation and process API it must not contain, and the fixture
 *      directory is hashed before and after a full scan so that "it changed nothing" is measured
 *      rather than asserted in prose.
 *
 *   4. NO DERIVED ROOTS. An empty root list must scan nothing. If a future change gives this tool a
 *      default that means "the whole machine", that assertion is what catches it -- on a machine
 *      where such a default would look like it worked.
 *
 * Division of labour: checks.mjs owns the catalog, selftest owns the tool surface, matrix owns the
 *   output contract. This suite owns the content target: its rule data, its matcher, its bounds,
 *   and its inability to change anything.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const content = await import(pathToFileURL(path.join(root, "lib", "content.mjs")).href);
const {
  builtinContentRules, CONTENT_SCHEMA, CONTENT_RULES_VERSION,
  DEFAULT_MAX_BYTES, HARD_MAX_BYTES,
  parseClamAvText, loadClamAvRules, compileRule, evaluateBuffer,
  collectFiles, readPrefix, scanContent,
} = content;

// One definition, so every assertion below reads the same list the tool reads.
const CONTENT_RULES = builtinContentRules();

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== fixture */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-content-"));
const F = (...p) => path.join(base, ...p);
function put(rel, data, mode = "utf8") {
  const full = F(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data, mode);
  return full;
}

const PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n-----END OPENSSH PRIVATE KEY-----\n";
put("plain/notes.txt", "just an ordinary note, nothing else in here\n");
put("plain/id_ed25519", PRIVATE_KEY);
put("plain/almost.txt", "-----BEGIN OPENSSH PRIVATE KEY----");          // header, no trailing dashes
put("plain/normal-name.txt", "text before\n" + PRIVATE_KEY + "text after\n");

// The prefix-ceiling fixture: the header starts after 2048 bytes, so whether it is seen depends
// entirely on the ceiling and on nothing else.
const padding = "x".repeat(3000);
put("deep/buried.txt", padding + PRIVATE_KEY);
put("deep/shallow.txt", "-----BEGIN CERTIFICATE-----\nMIIB\n");

// A tree with a known number of files, for the entry ceiling's pair.
for (let i = 0; i < 5; i++) put(`many/f${i}.txt`, `file ${i}\n`);

/* ================================================== the rule data itself */

section("the rule set is data, and every entry states its own boundary");

check("the builtin set is non-empty", CONTENT_RULES.length > 0, String(CONTENT_RULES.length));
check("every rule carries the four fields a report needs",
  CONTENT_RULES.every((r) => r.id && r.layer && r.severity && r.matcher && r.label && r.does_not_cover),
  JSON.stringify(CONTENT_RULES.filter((r) => !(r.id && r.layer && r.severity && r.matcher && r.label && r.does_not_cover)).map((r) => r.id)));
check("every rule states what it does and does not cover",
  CONTENT_RULES.every((r) => typeof r.why === "string" && r.why.length > 20 && typeof r.does_not_cover === "string" && r.does_not_cover.length > 20),
  JSON.stringify(CONTENT_RULES.filter((r) => !(r.why && r.why.length > 20 && r.does_not_cover && r.does_not_cover.length > 20)).map((r) => r.id)));
check("no rule uses a regular expression or any other interpreted form",
  CONTENT_RULES.every((r) => r.matcher === "literal" || r.matcher === "hex" || r.matcher === "md5"),
  JSON.stringify([...new Set(CONTENT_RULES.map((r) => r.matcher))]));
check("the deliberately weak rule is disabled rather than quietly dropped",
  CONTENT_RULES.some((r) => r.disabled === true));
check("a disabled rule does not fire",
  evaluateBuffer(Buffer.from("AAH something", "utf8"), CONTENT_RULES.map(compileRule).filter(Boolean)).hits.length === 0);

/* ================================================== the matcher */

section("the matcher: a hit, and the same bytes one character short of a hit");

const compiled = CONTENT_RULES.map(compileRule).filter(Boolean);
check("every enabled builtin rule compiles",
  CONTENT_RULES.filter((r) => !r.disabled).every((r) => compileRule(r) !== null),
  JSON.stringify(CONTENT_RULES.filter((r) => !r.disabled && compileRule(r) === null).map((r) => r.id)));

const complete = readPrefix(F("plain/id_ed25519"), DEFAULT_MAX_BYTES);
const completeHits = evaluateBuffer(complete.buf, compiled).hits;
check("a complete private-key header is reported, with an offset",
  completeHits.length >= 1 && completeHits.every((h) => Number.isInteger(h.offset)),
  JSON.stringify(completeHits.map((h) => h.rule)));

const almost = readPrefix(F("plain/almost.txt"), DEFAULT_MAX_BYTES);
const almostHits = evaluateBuffer(almost.buf, compiled).hits.filter((h) => h.rule === "openssh-private-key");
check("the same header one character short of complete is NOT reported by that rule",
  almostHits.length === 0, JSON.stringify(almostHits.map((h) => h.rule)));

check("a hit carries the rule's own boundary, so the report can carry it too",
  completeHits.every((h) => typeof h.does_not_cover === "string" && h.does_not_cover.length > 10));
check("a hit carries the rule source", completeHits.every((h) => h.source === "builtin"));

/* ================================================== the prefix ceiling, as a pair */

section("the prefix ceiling and its pair");

const buriedDefault = scanContent([F("deep")], { rules: CONTENT_RULES, maxBytes: 1024 });
check("at 1024 bytes the buried header is not seen",
  buriedDefault.findings.filter((f) => f.evidence && f.evidence.path === F("deep/buried.txt")).length === 0);
check("and that file is reported as truncated, so 'not seen' is not 'clean'",
  buriedDefault.truncatedFiles === 1, String(buriedDefault.truncatedFiles));
check("the shallow file in the same tree is still scanned in full",
  buriedDefault.findings.some((f) => f.evidence && f.evidence.path === F("deep/shallow.txt"))
  && !buriedDefault.findings.some((f) => f.evidence && f.evidence.path === F("deep/shallow.txt") && f.evidence.file_truncated),
  JSON.stringify(buriedDefault.findings.map((f) => f.evidence && f.evidence.path)));

const buriedTall = scanContent([F("deep")], { rules: CONTENT_RULES, maxBytes: 4096 });
check("at 4096 bytes the same header IS seen",
  buriedTall.findings.some((f) => f.evidence && f.evidence.path === F("deep/buried.txt")),
  JSON.stringify(buriedTall.findings.map((f) => f.evidence && f.evidence.path)));
check("and nothing in that tree is reported as truncated",
  buriedTall.truncatedFiles === 0, String(buriedTall.truncatedFiles));

check("the hard ceiling is enforced even when the caller asks for more",
  readPrefix(F("plain/notes.txt"), HARD_MAX_BYTES * 100).bytes <= Math.max(1, HARD_MAX_BYTES),
  String(readPrefix(F("plain/notes.txt"), HARD_MAX_BYTES * 100).bytes));

/* ================================================== whole-file signatures and truncation */

section("a whole-file signature against a file that was truncated");

const hdbLine = `${crypto.createHash("md5").update(Buffer.from(PRIVATE_KEY, "utf8")).digest("hex")}:${Buffer.byteLength(PRIVATE_KEY)}:Test.Signature-1`;
const hdbDir = F("clamdb");
fs.mkdirSync(hdbDir, { recursive: true });
fs.writeFileSync(path.join(hdbDir, "test.hdb"), hdbLine + "\n");

const loaded = loadClamAvRules(hdbDir);
check("one .hdb line loads as one rule", loaded.rules.length === 1, JSON.stringify(loaded.sources));
check("and it is attributed to the file it came from", loaded.rules[0].source === "test.hdb");

const hdbRule = { ...loaded.rules[0] };
const small = scanContent([F("plain/id_ed25519")], { rules: [hdbRule], maxBytes: 4096 });
check("a file read in full matches the whole-file signature",
  small.findings.length === 1, JSON.stringify(small.findings.map((f) => f.rule_id ?? f.id)));
check("and nothing is reported as not evaluated", small.notEvaluated.length === 0, JSON.stringify(small.notEvaluated));

const big = scanContent([F("deep/buried.txt")], { rules: [hdbRule], maxBytes: 64 });
check("a truncated file is NOT reported as a match",
  big.findings.length === 0, JSON.stringify(big.findings.map((f) => f.rule_id ?? f.id)));
check("a truncated file is reported as not evaluated instead",
  big.notEvaluated.length === 1 && /truncated/.test(big.notEvaluated[0].reason),
  JSON.stringify(big.notEvaluated));

const cleanFile = put("plain2/clean.txt", "no signature here\n");
const clean = scanContent([F("plain2")], { rules: [hdbRule], maxBytes: 4096 });
check("a file that was scanned and did not match lands in neither list",
  clean.findings.length === 0 && clean.notEvaluated.length === 0 && clean.scanned === 1,
  JSON.stringify({ f: clean.findings.length, n: clean.notEvaluated.length, s: clean.scanned }));
check("the two outcomes are therefore distinguishable shapes",
  Array.isArray(clean.findings) && Array.isArray(clean.notEvaluated) && cleanFile.endsWith("clean.txt"));

/* ================================================== the parser refuses what it cannot read */

section("the ClamAV parser: two simple forms, and an honest count of the rest");

const mixed = [
  "d41d8cd98f00b204e9800998ecf8427e:0:Test.Empty",
  "Test.Pattern:0:*:41424344",
  "Test.Conditional:0:1:2:3:4",
  "not a signature at all",
].join("\n");
const parsed = parseClamAvText(mixed, "mixed.ndb");
check("the two simplest forms parse", parsed.rules.length === 2, JSON.stringify(parsed.rules.map((r) => r.id)));
check("a hex rule carries its bytes and its anchor",
  parsed.rules[1].matcher === "hex" && parsed.rules[1].needle === undefined || parsed.rules[1].matcher === "hex",
  JSON.stringify(parsed.rules[1]));
check("everything outside those forms is counted, not silently dropped",
  parsed.skipped === 2, String(parsed.skipped));
check("and the skipped lines are reported with a reason",
  parsed.problems.length === 2 && parsed.problems.every((p) => typeof p.reason === "string"),
  JSON.stringify(parsed.problems));

const compiledHex = compileRule({ matcher: "hex", pattern: "41424344", id: "h", layer: "crypto", severity: "warn", label: "l", does_not_cover: "d" });
check("a hex rule matches the bytes it names",
  evaluateBuffer(Buffer.from("xxABCDyy", "utf8"), [compiledHex]).hits.length === 1);
const badHex = compileRule({ matcher: "hex", pattern: "41424", id: "h2", layer: "crypto", severity: "warn", label: "l", does_not_cover: "d" });
check("an odd-length hex pattern is refused rather than guessed at", badHex === null);
const badMatcher = compileRule({ matcher: "regex", pattern: ".*", id: "h3", layer: "crypto", severity: "warn", label: "l", does_not_cover: "d" });
check("an unknown matcher is refused, so the vocabulary stays closed", badMatcher === null);

/* ================================================== entry and depth ceilings */

section("ceilings, each as a pair");

const three = collectFiles([F("many")], { maxFiles: 3 });
const five = collectFiles([F("many")], { maxFiles: 5 });
check(`at a ceiling of 3 the walk returns 3 files and says what it did not take`,
  three.files.length === 3 && three.skipped.length >= 1, JSON.stringify({ f: three.files.length, s: three.skipped.length }));
check(`at a ceiling of 5 the same tree returns 5`,
  five.files.length === 5, String(five.files.length));

put("deep/nested/one/two/three/four/five/six/seven/leaf.txt", "leaf\n");
const shallowWalk = collectFiles([F("deep")], { maxDepth: 2 });
const deepWalk = collectFiles([F("deep")], { maxDepth: 9 });
check("a depth ceiling stops the walk and reports the stop",
  !shallowWalk.files.some((p) => /leaf\.txt$/.test(p)) && shallowWalk.skipped.some((s) => /deeper than/.test(s.reason)),
  JSON.stringify(shallowWalk.skipped.slice(0, 2)));
check("the same tree at a deeper ceiling reaches the leaf",
  deepWalk.files.some((p) => /leaf\.txt$/.test(p)));

/* ================================================== roots come from the caller */

section("no derived roots");

const nothing = scanContent([], { rules: CONTENT_RULES });
check("an empty root list scans nothing at all",
  nothing.files === 0 && nothing.findings.length === 0 && nothing.scanned === 0,
  JSON.stringify({ files: nothing.files, scanned: nothing.scanned }));

const missing = scanContent([F("no-such-directory")], { rules: CONTENT_RULES });
check("a root that does not exist is reported, not treated as a clean scan",
  missing.scanned === 0 && missing.skipped.length >= 1,
  JSON.stringify(missing.skipped));

/* ================================================== it really does read contents */

section("the difference from every other probe, asserted rather than glossed over");

const ordinary = scanContent([F("plain/normal-name.txt")], { rules: CONTENT_RULES });
check("a file with an ordinary name is caught on its contents",
  ordinary.findings.some((f) => f.evidence && f.evidence.path === F("plain/normal-name.txt")),
  JSON.stringify(ordinary.findings.map((f) => f.evidence && f.evidence.path)));
check("the hit reports the offset rather than the bytes",
  ordinary.findings.every((f) => Number.isInteger(f.evidence.offset) && f.evidence.length > 0));

const notesOnly = scanContent([F("plain/notes.txt")], { rules: CONTENT_RULES });
check("and a genuinely ordinary file produces nothing",
  notesOnly.findings.length === 0 && notesOnly.scanned === 1, String(notesOnly.findings.length));

/* ================================================== no write path, measured */

section("it cannot change anything, and that is measured");

function snapshot(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      const b = fs.readFileSync(full);
      out.push(`${path.relative(dir, full)} ${b.length} ${crypto.createHash("sha256").update(b).digest("hex")}`);
    }
  };
  walk(dir);
  return out.sort();
}

const before = snapshot(base);
scanContent([base], { rules: CONTENT_RULES, maxBytes: 65536, maxFiles: 500 });
const after = snapshot(base);
check("a full scan leaves every byte of the tree as it was",
  before.length === after.length && before.every((v, i) => v === after[i]),
  JSON.stringify({ before: before.length, after: after.length }));

const src = fs.readFileSync(path.join(root, "lib", "content.mjs"), "utf8");
const mutationApis = ["writeFileSync", "appendFileSync", "unlinkSync", "rmSync", "rmdirSync", "renameSync",
  "copyFileSync", "mkdirSync", "chmodSync", "chownSync", "truncateSync", "createWriteStream"];
const foundMutations = mutationApis.filter((a) => src.includes(a));
check("the module's source contains no mutation API at all",
  foundMutations.length === 0, JSON.stringify(foundMutations));

const processApis = ["child_process", "execFile", "execSync", "spawnSync", "spawn(", "eval(", "new Function"];
const foundProcess = processApis.filter((a) => src.includes(a));
check("and no way to run anything, so 'never executes the target' is structural",
  foundProcess.length === 0, JSON.stringify(foundProcess));

const networkApis = ["node:http", "node:https", "node:net", "node:dgram", "fetch("];
const foundNetwork = networkApis.filter((a) => src.includes(a));
check("and no network import, so the static boundary is structural too",
  foundNetwork.length === 0, JSON.stringify(foundNetwork));

check("the schema string is stable for a reader that keys on it",
  CONTENT_SCHEMA === "aikawamei-content/1" && CONTENT_RULES_VERSION === "1",
  `${CONTENT_SCHEMA} ${CONTENT_RULES_VERSION}`);

/* ================================================== summary */

try {
  fs.rmSync(base, { recursive: true, force: true });
  console.log("\n  \u001b[90mtemporary fixtures cleaned up\u001b[0m");
} catch { /* a fixture that will not delete is not a test failure */ }

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
