#!/usr/bin/env node
/**
 * Vault suite -- drives lib/vault.mjs: the seal, and the chain.
 *
 * Why this needs its own suite:
 *
 *   1. Both properties are claims about what CANNOT be done, and a claim of that shape is worth
 *      nothing unless the failure is tested. "An edited record is detected" means every way of
 *      editing one has to be tried: change a line, delete one, insert one, swap two, blank one out.
 *      "A wrong passphrase opens nothing" means an altered payload, tag, nonce and salt each have to
 *      be refused -- and each with an input that violates exactly that one field, so a check cannot
 *      pass because an earlier check rejected first.
 *
 *   2. The chain CANNOT see its own tail being cut, and that limit is asserted rather than left to
 *      be discovered: the same truncated chain that is refused against a kept receipt must verify
 *      as intact without one. An honest limit that has a test is a documented limit; one without a
 *      test is a surprise.
 *
 *   3. Integrity and confidentiality are separate properties here, and the separation is the point:
 *      the whole point of hashing the SEALED line is that someone who cannot read a single entry can
 *      still prove the sequence was not altered. That is asserted directly, on a chain that was
 *      never opened.
 *
 * Hermeticity: every tamper case is built in memory, so the suite is about the mechanism rather than
 *   about a filesystem -- EXCEPT section E, which exists precisely because the file half has its own
 *   ways to go wrong. Section E writes into a temp directory it removes afterwards, and it is the
 *   only part of this suite that touches a disk.
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const {
  VAULT_SCHEMA, VAULT_CIPHER, VAULT_KDF, GENESIS,
  appendRecord, appendTo, deriveKey, digestsEqual, isEnvelope, lineHash, linesOf,
  makeRecord, openValue, readChain, sealValue, verifyChain, verifyFile,
} = await import(pathToFileURL(path.join(root, "lib", "vault.mjs")).href);

let pass = 0, fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

const PASSPHRASE = "correct horse battery staple";
const OTHER = "correct horse battery stapl";
// The production cost is ~32 MB and ~100 ms per derivation; a suite that paid it forty times would
// be slow enough to be skipped. The parameters travel in the envelope, so a cheap seal is opened by
// the same code path as an expensive one -- what is being tested is the mechanism, not the cost.
const CHEAP = { n: 1 << 10, r: 8, p: 1 };

/* ====================== A. the seal ====================== */

section("A. sealing a value");

const value = { kind: "directory", path: "C:/Users/someone/AppData/Local/thing", note: "third party" };
const sealed = sealValue(PASSPHRASE, value, { cost: CHEAP });

check("the envelope names itself", sealed.format === VAULT_SCHEMA && sealed.cipher === VAULT_CIPHER && sealed.kdf === VAULT_KDF,
  JSON.stringify({ f: sealed.format, c: sealed.cipher, k: sealed.kdf }));
check("it is structurally an envelope", isEnvelope(sealed) === true);
check("the round trip returns the value unchanged",
  JSON.stringify(openValue(PASSPHRASE, sealed)) === JSON.stringify(value), JSON.stringify(openValue(PASSPHRASE, sealed)));
check("the plaintext is not in the envelope",
  !JSON.stringify(sealed).includes("AppData") && !JSON.stringify(sealed).includes("someone"));
check("the cost is recorded, so an opener does not have to guess", sealed.kdf_params.n === CHEAP.n, JSON.stringify(sealed.kdf_params));
check("sealing the same value twice produces a different envelope",
  sealValue(PASSPHRASE, value, { cost: CHEAP }).payload !== sealed.payload);
check("and a different nonce and salt", (() => {
  const b = sealValue(PASSPHRASE, value, { cost: CHEAP });
  return b.nonce !== sealed.nonce && b.salt !== sealed.salt;
})());

// Each rejection is driven by an input that violates exactly one field.
const wrongPass = (() => { try { openValue(OTHER, sealed); return "opened"; } catch (e) { return "refused"; } })();
check("a wrong passphrase opens nothing", wrongPass === "refused", wrongPass);
for (const [field, mutate] of [
  ["payload", (env) => ({ ...env, payload: Buffer.from("other").toString("base64") })],
  ["tag", (env) => ({ ...env, tag: env.tag.replace(/^../, env.tag.startsWith("00") ? "11" : "00") })],
  ["nonce", (env) => ({ ...env, nonce: env.nonce.replace(/^../, env.nonce.startsWith("00") ? "11" : "00") })],
  ["salt", (env) => ({ ...env, salt: env.salt.replace(/^../, env.salt.startsWith("00") ? "11" : "00") })],
]) {
  const altered = mutate(sealed);
  const outcome = (() => { try { openValue(PASSPHRASE, altered); return "opened"; } catch { return "refused"; } })();
  // The salt case derives a different key, so it must also fail; asserting all four together would
  // pass for a check that only ever looked at the tag.
  check(`an altered ${field} is refused`, outcome === "refused", outcome);
}
check("a structure that is not an envelope is refused", (() => {
  try { openValue(PASSPHRASE, { format: "something-else" }); return "opened"; } catch { return "refused"; }
})() === "refused");
check("a short salt is not a well-formed envelope", !isEnvelope({ ...sealed, salt: "ab" }));
check("a null is not a well-formed envelope", !isEnvelope(null));
check("the derived key depends on the salt", !deriveKey(PASSPHRASE, "00".repeat(16), CHEAP).equals(deriveKey(PASSPHRASE, "11".repeat(16), CHEAP)));

/* ====================== B. the chain ====================== */

section("B. the chain");

let chain = [];
for (const kind of ["scan", "seal", "refuse"]) {
  chain = appendTo(chain, { kind, sealed: sealValue(PASSPHRASE, { what: kind }, { cost: CHEAP }), note: null }).lines;
}
const good = verifyChain(chain);
check("a fresh chain verifies", good.ok === true && good.length === 3, JSON.stringify(good));
check("it reports a head", typeof good.head === "string" && good.head.length === 64);
check("the head is the digest of the last line", good.head === lineHash(chain[2]));
check("the first record starts the chain", JSON.parse(chain[0]).prev === GENESIS);

// Every way of editing it. Each case is a DIFFERENT index from the others, so a check that always
// reported "index 0" would fail here rather than pass everywhere.
const tampered = {
  "an edited line": (() => { const c = chain.slice(); const r = JSON.parse(c[1]); r.kind = "edited"; c[1] = JSON.stringify(r); return c; })(),
  "a deleted line": (() => chain.filter((_, i) => i !== 1))(),
  "an inserted line": (() => { const c = chain.slice(); c.splice(1, 0, JSON.stringify({ schema: VAULT_SCHEMA, at: "x", prev: GENESIS })); return c; })(),
  "two swapped lines": (() => { const c = chain.slice(); [c[0], c[1]] = [c[1], c[0]]; return c; })(),
  "a blanked line": (() => { const c = chain.slice(); c[1] = ""; return c; })(),
  "a line of nonsense": (() => { const c = chain.slice(); c[1] = "{not json"; return c; })(),
};
for (const [what, lines] of Object.entries(tampered)) {
  const r = verifyChain(lines);
  check(`${what} is detected`, r.ok === false && r.broken !== null, JSON.stringify(r));
  check(`${what} names where to look`, Number.isInteger(r.broken?.index) && r.broken.index >= 0 && r.broken.index <= lines.length,
    JSON.stringify(r.broken));
}
check("a deleted line is caught at the record that no longer links",
  verifyChain(tampered["a deleted line"]).broken.index === 1, JSON.stringify(verifyChain(tampered["a deleted line"]).broken));
check("the first record must start the chain",
  verifyChain([JSON.stringify({ schema: VAULT_SCHEMA, at: "x", prev: "deadbeef" })]).broken?.index === 0);
check("an empty chain is not an error", verifyChain([]).ok === true);

// Integrity without the key: the chain is over the sealed text, so it can be verified by someone who
// cannot open a single entry. This is the separation the module exists for.
check("the chain verifies WITHOUT the passphrase",
  verifyChain(chain).ok === true && (() => { try { openValue("not the passphrase", JSON.parse(chain[0]).sealed); return false; } catch { return true; } })());

/* ====================== C. the limit, asserted ====================== */

section("C. what the chain cannot see");

const cut = chain.slice(0, 2);
check("a chain cut short still verifies on its own terms", verifyChain(cut).ok === true,
  JSON.stringify(verifyChain(cut)));
check("...and that is exactly why the limit is stated rather than implied",
  verifyChain(cut).length === 2 && good.length === 3);
check("a kept receipt catches the cut",
  verifyChain(cut, { expectLength: good.length }).ok === false && verifyChain(cut, { expectLength: good.length }).truncation_detected === true,
  JSON.stringify(verifyChain(cut, { expectLength: good.length })));
check("a kept head catches a rewritten tail",
  verifyChain(chain, { expectHead: "00".repeat(32) }).ok === false,
  JSON.stringify(verifyChain(chain, { expectHead: "00".repeat(32) })));
check("the matching receipt passes, so the check is not simply always failing",
  verifyChain(chain, { expectLength: good.length, expectHead: good.head }).ok === true,
  JSON.stringify(verifyChain(chain, { expectLength: good.length, expectHead: good.head })));

/* ====================== D. small helpers ====================== */

section("D. the edges");

check("linesOf drops the trailing newline but keeps interior blanks",
  JSON.stringify(linesOf("a\n\nb\n")) === JSON.stringify(["a", "", "b"]), JSON.stringify(linesOf("a\n\nb\n")));
check("linesOf tolerates nothing", JSON.stringify(linesOf("")) === JSON.stringify([]) && JSON.stringify(linesOf(null)) === JSON.stringify([]));
check("appendTo tolerates a missing array", verifyChain(appendTo(null, { kind: "x" }).lines).ok === true);
check("makeRecord carries what it is given",
  JSON.parse(makeRecord({ kind: "k", note: "n", at: "T" }).line).note === "n");
check("digestsEqual holds for equal values", digestsEqual("ab", "ab") === true);
check("digestsEqual does not hold for different ones", digestsEqual("ab", "ac") === false);
check("digestsEqual does not hold across lengths", digestsEqual("ab", "abc") === false);
check("digestsEqual tolerates nothing", digestsEqual(null, null) === true && digestsEqual(null, "a") === false);

/* ====================== E. the file ====================== */

section("E. the chain on disk");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-vault-"));
const chainFile = path.join(tmp, "nested", "chain.jsonl");

check("a chain that does not exist is reported rather than thrown",
  verifyFile(chainFile).exists === false && verifyFile(chainFile).ok === false,
  JSON.stringify(verifyFile(chainFile)));
check("reading a chain that does not exist gives null", readChain(chainFile) === null);

const first = appendRecord(chainFile, { kind: "one", note: "n" });
check("appending creates the file and its directory", fs.existsSync(chainFile) && first.length === 1);
check("...and the record links to nothing, because it is the first", JSON.parse(readChain(chainFile)[0]).prev === GENESIS);
const second = appendRecord(chainFile, { kind: "two", sealed: sealValue(PASSPHRASE, { p: 1 }, { cost: CHEAP }) });
check("a second append lengthens the chain", second.length === 2);
check("the file holds one line per record", readChain(chainFile).length === 2, String(readChain(chainFile).length));
check("the chain on disk verifies", verifyFile(chainFile).ok === true, JSON.stringify(verifyFile(chainFile)));
check("a receipt taken from it verifies it again",
  verifyFile(chainFile, { expectLength: second.length, expectHead: second.hash }).ok === true);

// Truncation, on the real file: the same shorter chain passes on its own terms and is caught
// against the receipt. Without the pair, a check that always failed would look the same.
const whole = fs.readFileSync(chainFile, "utf8");
fs.writeFileSync(chainFile, whole.split("\n").slice(0, 1).join("\n") + "\n");
check("a cut tail still verifies on its own terms", verifyFile(chainFile).ok === true);
check("a cut tail is caught against the receipt",
  verifyFile(chainFile, { expectLength: second.length }).truncation_detected === true,
  JSON.stringify(verifyFile(chainFile, { expectLength: second.length })));
fs.writeFileSync(chainFile, whole);

// An edit made with an editor, which is how a record would actually be altered.
const edited = fs.readFileSync(chainFile, "utf8").split("\n");
const asObject = JSON.parse(edited[0]);
asObject.note = "edited";
edited[0] = JSON.stringify(asObject);
fs.writeFileSync(chainFile, edited.join("\n"));
check("a line edited on disk is caught",
  verifyFile(chainFile).ok === false && verifyFile(chainFile).broken.index === 1,
  JSON.stringify(verifyFile(chainFile).broken));
fs.writeFileSync(chainFile, whole);

// A forged record appended by someone who can write the file but not sign it.
const forged = { schema: VAULT_SCHEMA, at: "x", prev: "00".repeat(32), kind: "forged", note: null, sealed: null };
fs.appendFileSync(chainFile, JSON.stringify(forged) + "\n");
check("an appended forgery is caught at its own index",
  verifyFile(chainFile).broken?.index === 2, JSON.stringify(verifyFile(chainFile).broken));
fs.writeFileSync(chainFile, whole);

check("the file is left as it was found", verifyFile(chainFile, { expectLength: second.length, expectHead: second.hash }).ok === true);

// A path that exists but is not a file. "There is no chain here" and "I could not read what is
// here" are different answers, and only the first one is an answer -- so this must propagate rather
// than be reported as an empty chain, which would read as a vault that was never written.
const notAFile = path.join(tmp, "a-directory");
fs.mkdirSync(notAFile, { recursive: true });
check("reading a directory throws rather than reporting an empty chain", (() => {
  try { readChain(notAFile); return "returned"; } catch { return "threw"; }
})() === "threw");
check("appending to a directory throws too", (() => {
  try { appendRecord(notAFile, { kind: "x" }); return "returned"; } catch { return "threw"; }
})() === "threw");

try { fs.rmSync(tmp, { recursive: true, force: true }); console.log("  \u001b[90mtemporary chain removed\u001b[0m"); } catch {}

/* ====================== summary ====================== */

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
