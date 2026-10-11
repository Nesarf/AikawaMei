#!/usr/bin/env node
/**
 * Self-check suite -- drives lib/selfcheck.mjs, the part that watches the installation itself.
 *
 * Why this needs its own suite:
 *
 *   1. The claim is a DIFF, and a diff has four outcomes that all look alike from the outside: added,
 *      removed, changed, unchanged. A comparison that reported every file as changed would pass a
 *      one-sided test of "it noticed the edit", so every case here is asserted against its control --
 *      the edit is detected AND the untouched files beside it are reported as untouched.
 *
 *   2. Symmetry is the property that catches the classic defect. A file removed from the second
 *      manifest and a file added to it are different answers, and an implementation that walked only
 *      one side would silently report one of them as the other, or as nothing.
 *
 *   3. What the module CANNOT do is the most important part of it, and it is asserted rather than
 *      left to the prose: an installation that has been removed cannot run, so silence is not an
 *      answer -- and the list of what would answer instead has to name something that actually would.
 *
 * Hermeticity: a small tree is built in a temp directory and removed at the end. The digests are real
 * digests of real bytes, because a comparison tested against fabricated hashes is testing its own
 * string handling.
 */

import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const {
  SELFCHECK_SCHEMA, SELF_NOT_POSSIBLE, SELF_PATTERNS,
  compareManifests, manifestOf, readManifest, selfBoundary, selfFiles,
} = await import(pathToFileURL(path.join(root, "lib", "selfcheck.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ====================== fixture ====================== */

const base = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-self-"));
const F = (...p) => path.join(base, ...p);
function put(rel, data) {
  const full = F(rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data);
  return full;
}
put("lib/core.mjs", "export const a = 1;\n");
put("lib/checks.mjs", "export const b = 2;\n");
put("cli/index.mjs", "console.log(1);\n");
put("mcp/index.mjs", "console.log(2);\n");
put("package.json", '{"name":"x"}\n');
put(".gitattributes", "* text=auto\n");
put("README.md", "not part of what decides what it does\n");
put("lib/nested/deep.mjs", "// past the depth bound\n");

/* ====================== A. what counts as the installation ====================== */

section("A. which files are the installation");

const files = selfFiles(base);
check("the code directories are included",
  files.includes("lib/core.mjs") && files.includes("cli/index.mjs") && files.includes("mcp/index.mjs"),
  JSON.stringify(files));
check("the manifest that names what it is is included",
  files.includes("package.json") && files.includes(".gitattributes"));
check("prose is not: a README does not change what the tool does",
  !files.includes("README.md"), JSON.stringify(files));
check("the tree walk is bounded rather than wandering",
  !files.includes("lib/nested/deep.mjs"), JSON.stringify(files));
check("the list is sorted, so two runs produce the same manifest",
  JSON.stringify(files) === JSON.stringify([...files].sort()));
check("the patterns are stated rather than implied", SELF_PATTERNS.length >= 4);

/* ====================== B. the manifest ====================== */

section("B. the manifest");

const first = manifestOf(base);
check("every file the installation consists of is in it", first.count === files.length, String(first.count));
check("each entry carries a real digest", first.entries.every((e) => /^[0-9a-f]{64}$/.test(e.sha256 ?? "")),
  JSON.stringify(first.entries.filter((e) => !/^[0-9a-f]{64}$/.test(e.sha256 ?? "")).map((e) => e.path)));
check("the digests differ between files, so they are digests of the content",
  first.entries.find((e) => e.path === "lib/core.mjs").sha256 !== first.entries.find((e) => e.path === "lib/checks.mjs").sha256);
check("a missing file would be recorded as absent rather than dropped",
  manifestOf(base, ["lib/core.mjs", "lib/not-here.mjs"]).entries[1].present === false);
check("the schema is versioned", /^aikawamei-selfcheck\/\d+$/.test(SELFCHECK_SCHEMA), SELFCHECK_SCHEMA);

/* ====================== C. the diff, in all four directions ====================== */

section("C. what changed");

const same = compareManifests(first, manifestOf(base));
check("an unchanged installation compares clean", same.clean === true && same.unchanged.length === files.length,
  JSON.stringify({ added: same.added, removed: same.removed, changed: same.changed.map((c) => c.path) }));

fs.writeFileSync(F("lib/checks.mjs"), "export const b = 999;\n");
put("lib/added.mjs", "// new\n");
fs.rmSync(F("cli/index.mjs"));

const after = manifestOf(base);
const diff = compareManifests(first, after);
check("an edited file is reported as changed", diff.changed.some((c) => c.path === "lib/checks.mjs"), JSON.stringify(diff.changed));
check("...and the change names both digests, so a reader can see it is a real edit",
  diff.changed[0].before !== diff.changed[0].after && /^[0-9a-f]{64}$/.test(diff.changed[0].before), JSON.stringify(diff.changed[0]));
check("a removed file is reported as removed, not as unchanged",
  diff.removed.includes("cli/index.mjs"), JSON.stringify(diff.removed));
check("an added file is reported as added", diff.added.includes("lib/added.mjs"), JSON.stringify(diff.added));
check("a changed installation is not clean", diff.clean === false);
// The control that gives the whole comparison its meaning: the files nobody touched.
check("the files that were NOT touched are reported as untouched",
  diff.unchanged.includes("lib/core.mjs") && diff.unchanged.includes("package.json"), JSON.stringify(diff.unchanged));
// Two identities, not one: the AFTER side is what is present now (added + changed + unchanged), and
// the BEFORE side is what was present then (removed + changed + unchanged). Asserting a single total
// would only hold when nothing was added or removed, which is the case where it proves least.
const sums = { after: diff.added.length + diff.changed.length + diff.unchanged.length,
               before: diff.removed.length + diff.changed.length + diff.unchanged.length };
check("every file on each side lands in exactly one list",
  sums.after === after.count && sums.before === first.count,
  JSON.stringify({ ...sums, afterCount: after.count, beforeCount: first.count }));

// An empty manifest on one side must not read as "everything was removed" if that side was never
// captured -- the caller gets to tell the difference because the lists are separate.
const empty = compareManifests({ entries: [] }, after);
check("a comparison against nothing reports everything as added, not as unchanged",
  empty.added.length === after.count && empty.unchanged.length === 0, JSON.stringify({ a: empty.added.length, u: empty.unchanged.length }));
check("and a comparison against a manifest that is not there does not throw",
  compareManifests(null, after).added.length === after.count);

/* ====================== D. a manifest that was kept ====================== */

section("D. a manifest that was kept");

const keptPath = F("kept/manifest.json");
fs.mkdirSync(path.dirname(keptPath), { recursive: true });
fs.writeFileSync(keptPath, JSON.stringify(manifestOf(base)));
check("a kept manifest can be read back", readManifest(keptPath)?.count === after.count, JSON.stringify(readManifest(keptPath)?.count));
check("and compared against the present state",
  compareManifests(readManifest(keptPath), manifestOf(base)).clean === true);
check("a manifest that is not JSON is null rather than a throw", readManifest(F("lib/core.mjs")) === null);
check("a manifest that is not there is null too", readManifest(F("no-such.json")) === null);
check("JSON that is not a manifest is refused rather than half-read",
  (() => { fs.writeFileSync(F("kept/other.json"), '{"entries":"no"}'); return readManifest(F("kept/other.json")) === null; })());

/* ====================== E. what it cannot do ====================== */

section("E. the limits, asserted rather than described");

// The wording lives in `why`, not in the question, so the assertion looks where the claim is.
check("the list names the removal it cannot report",
  SELF_NOT_POSSIBLE.some((q) => /removed/.test(q.why) && /cannot report/.test(q.why)),
  JSON.stringify(SELF_NOT_POSSIBLE.map((q) => [q.question, q.why])));
check("...and offers something that would actually answer it",
  SELF_NOT_POSSIBLE[0].answerable_by.length > 40 && /off this machine|another machine/i.test(SELF_NOT_POSSIBLE[0].answerable_by),
  SELF_NOT_POSSIBLE[0].answerable_by);
check("it states that it prevents nothing, rather than leaving that to be assumed",
  SELF_NOT_POSSIBLE.some((q) => /prevented/.test(q.question) && /nothing here prevents/.test(q.why)));
check("and it points at an operating-system control for that, not at itself",
  /permission|ACL|immutable|backup/i.test(SELF_NOT_POSSIBLE[1].answerable_by), SELF_NOT_POSSIBLE[1].answerable_by);
check("attribution is refused explicitly", SELF_NOT_POSSIBLE.some((q) => /who changed/i.test(q.question)));
check("the one-line boundary says both things: it detects, and it prevents nothing",
  /detects/.test(selfBoundary()) && /prevents nothing/.test(selfBoundary()), selfBoundary());

/* ====================== F. the tool ====================== */

section("F. the tool");

const tools = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const vaultMod = await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href);
const selfTool = tools.TOOLS.find((t) => t.name === "aikawamei_self");
const installation = F("install");
put("install/lib/core.mjs", "export const a = 1;\n");
put("install/lib/checks.mjs", "export const b = 2;\n");
put("install/cli/index.mjs", "console.log(1);\n");
put("install/package.json", '{"name":"x"}\n');
put("install/.gitattributes", "* text=auto\n");

check("the tool exists and is registered", !!selfTool);
check("it declares that it writes, because it can keep a manifest",
  selfTool.operations.includes("writes"), JSON.stringify(selfTool.operations));

const baselinePath = F("self/base.json");
const captured = await selfTool.execute({ root: installation, out: baselinePath });
check("it captures a manifest and writes it where it was told",
  captured.manifest_count === 5 && fs.existsSync(baselinePath),
  JSON.stringify({ n: captured.manifest_count, w: captured.written }));
check("with nothing to compare against it says so rather than reporting clean",
  captured.diff === null && captured.baseline === null);
check("the limits travel with the answer",
  captured.not_possible.length === 3 && /prevents nothing/.test(captured.boundary_note), String(captured.boundary_note));

// The comparison, on a real edit and a real deletion.
fs.writeFileSync(path.join(installation, "lib/checks.mjs"), "export const b = 999;\n");
fs.rmSync(path.join(installation, "cli/index.mjs"));
const compared = await selfTool.execute({ root: installation, baseline: baselinePath });
check("an edited file is named", compared.diff.changed.some((c) => c.path === "lib/checks.mjs"), JSON.stringify(compared.diff.changed));
check("a deleted file is named", compared.diff.removed.includes("cli/index.mjs"), JSON.stringify(compared.diff.removed));
check("an untouched file is reported as untouched, which is the control",
  compared.diff.unchanged.includes("package.json"), JSON.stringify(compared.diff.unchanged));
check("the result is not called clean", compared.diff.clean === false);
check("nothing was written this time, because no output was named", compared.written === null);

// A chain it can verify, and the truncation only a receipt catches.
const chainPath = F("self/chain.jsonl");
vaultMod.appendRecord(chainPath, { kind: "one" });
vaultMod.appendRecord(chainPath, { kind: "two" });
const chainOk = await selfTool.execute({ root: installation, chain: chainPath });
check("it verifies a record chain without a passphrase",
  chainOk.chain?.ok === true && chainOk.chain.length === 2, JSON.stringify(chainOk.chain));
const cutChain = F("self/cut.jsonl");
fs.writeFileSync(cutChain, fs.readFileSync(chainPath, "utf8").split("\n")[0] + "\n");
check("a cut chain passes on its own terms",
  (await selfTool.execute({ root: installation, chain: cutChain })).chain.ok === true);
check("...and is caught against the receipt the tool itself handed out",
  (await selfTool.execute({ root: installation, chain: cutChain, expect_length: chainOk.chain.receipt.length })).chain.truncation_detected === true);
check("a chain that is not there is an answer, not a crash",
  (await selfTool.execute({ root: installation, chain: F("self/absent.jsonl") })).chain.exists === false);

/* ====================== G. signing, and the start-up gate ====================== */

section("G. signing, and the start-up gate");

const { canonicalManifest, generateSigningKeys, publicKeyOf, selfGate, signManifest, verifyManifestSignature } =
  await import(pathToFileURL(path.join(root, "lib", "selfcheck.mjs")).href);

const keys = generateSigningKeys();
const pub = keys.public_key_pem;
const signed = manifestOf(installation);
const sig = signManifest(signed, keys.private_key_pem);

check("a signed manifest verifies with its public key", verifyManifestSignature(signed, sig, pub) === true);
check("...and does not verify with a different key",
  verifyManifestSignature(signed, sig, generateSigningKeys().public_key_pem) === false);
check("...and does not verify a manifest that changed",
  (() => { const t = JSON.parse(JSON.stringify(signed)); t.entries[1].sha256 = "0".repeat(64); return verifyManifestSignature(t, sig, pub) === false; })());
check("...and does not verify a signature that changed",
  verifyManifestSignature(signed, Buffer.from("nope").toString("base64"), pub) === false);
check("nonsense does not throw, it returns false",
  verifyManifestSignature(signed, sig, "not a key") === false && verifyManifestSignature(null, null, pub) === false);
check("the public half can be derived from the private one", /BEGIN PUBLIC KEY/.test(publicKeyOf(keys.private_key_pem) ?? ""));
// Two different refusals, and the first version of this test only exercised the second: a MALFORMED
// key throws inside createPrivateKey before the type check is ever reached, so the check that names
// the key type was never executed. A VALID key of the wrong type is what reaches it, so the curve is
// generated rather than written out.
const ecKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const ecPem = ecKeys.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
check("a VALID key of the wrong type is refused, and the error names the type",
  (() => { try { signManifest(signed, ecPem); return false; } catch (e) { return /ed25519/.test(String(e.message)); } })());
check("a malformed key is refused too, by a different path",
  (() => { try { signManifest(signed, "-----BEGIN PRIVATE KEY-----\nnotakey\n-----END PRIVATE KEY-----"); return false; } catch { return true; } })());
check("a public key of the wrong type does not verify, and does not throw",
  verifyManifestSignature(signed, sig, ecKeys.publicKey.export({ type: "spki", format: "pem" }).toString()) === false);
check("the public half of something that is not a key is null rather than a throw", publicKeyOf("nonsense") === null);

// The property that makes a signature portable: the bytes signed must not depend on the order the
// JSON happened to be written in, or a manifest that survived a round trip through another tool would
// fail to verify while being identical in every field that matters.
const shuffled = JSON.parse(JSON.stringify(signed));
shuffled.entries = shuffled.entries.slice().reverse();
check("a reordered manifest canonicalises to the same bytes", canonicalManifest(shuffled) === canonicalManifest(signed));
check("...and therefore still verifies", verifyManifestSignature(shuffled, sig, pub) === true);
check("...while a changed field does not", (() => {
  const t = JSON.parse(JSON.stringify(signed));
  t.entries[0].size = (t.entries[0].size ?? 0) + 1;
  return canonicalManifest(t) !== canonicalManifest(signed);
})());

const gateBase = F("gate");
put("gate/lib/core.mjs", "export const a = 1;\n");
put("gate/package.json", '{"name":"x"}\n');
const gateManifest = F("gate-keep.json");
fs.writeFileSync(gateManifest, JSON.stringify(manifestOf(gateBase)));

check("the gate is off unless it is asked for", selfGate(gateBase, null, {}).armed === false);
check("...and off does not mean broken", selfGate(gateBase, null, {}).ok === true);
check("an armed gate passes an unchanged installation", selfGate(gateBase, gateManifest).ok === true);
check("...and reports how many files it checked", selfGate(gateBase, gateManifest).checked === 2, String(selfGate(gateBase, gateManifest).checked));

fs.writeFileSync(path.join(gateBase, "lib/core.mjs"), "export const a = 2;\n");
const failed = selfGate(gateBase, gateManifest);
check("an armed gate REFUSES a changed installation", failed.ok === false);
check("...and names the file that changed", /core\.mjs/.test(failed.message), failed.message);
check("...and says that nothing was repaired, rather than leaving it to be assumed",
  /Nothing has been repaired/.test(failed.message), failed.message);
check("a baseline that cannot be read is refused rather than ignored",
  selfGate(gateBase, F("gate-absent.json")).ok === false);
check("the environment variable is what arms it",
  selfGate(gateBase, null, { AIKAWAMEI_VERIFY_SELF: gateManifest }).armed === true);

// The tool's own two fields, end to end.
const keyPath = F("sign.key");
fs.writeFileSync(keyPath, keys.private_key_pem);
const pubPath = F("sign.pub");
fs.writeFileSync(pubPath, pub);
const signedRun = await selfTool.execute({ root: installation, sign_key: keyPath });
check("the tool can sign the manifest it reports", typeof signedRun.signature?.signature === "string", JSON.stringify(signedRun.signature).slice(0, 120));
const checkedRun = await selfTool.execute({ root: installation, verify_key: pubPath, signature: signedRun.signature.signature });
check("...and check a signature against a public key", checkedRun.signature_check?.valid === true, JSON.stringify(checkedRun.signature_check));
check("...and says so when it does not match",
  (await selfTool.execute({ root: installation, verify_key: pubPath, signature: "AAAA" })).signature_check?.valid === false);

/* ====================== summary ====================== */

try { fs.rmSync(base, { recursive: true, force: true }); console.log("\n  \u001b[90mtemporary installation removed\u001b[0m"); } catch {}

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
