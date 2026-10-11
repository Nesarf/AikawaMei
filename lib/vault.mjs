/**
 * AikawaMei - the operation record
 *
 * WHY THIS EXISTS
 * ---------------
 * A tool that seals other people's sensitive material and refuses things has to be able to show
 * what it did. Two properties are needed, and they are different properties:
 *
 *   INTEGRITY      A record that can be edited without leaving a trace is worse than no record,
 *                  because it can be produced as evidence of something that never happened. So the
 *                  records are CHAINED: each one carries the hash of the line before it, and any
 *                  edit, deletion, insertion or reorder breaks the link at the first affected
 *                  record. Verification needs NO key -- the chain is over the sealed text, so
 *                  integrity is checkable by someone who cannot read a single entry.
 *
 *   CONFIDENTIALITY  What a run sealed is frequently the thing that must not be readable: a path
 *                  under someone else's profile, a token, a victim's details. Every entry's payload
 *                  is sealed with AES-256-GCM under a key derived from a passphrase with scrypt, so
 *                  holding the file is not holding the contents.
 *
 * WHAT IT DELIBERATELY DOES NOT COVER
 * -----------------------------------
 *   * **Removal from the end.** A chain cannot see its own tail being cut: the remaining records are
 *     all still perfectly linked. `verifyChain` therefore accepts an expectation -- the length and
 *     the head hash a previous verification reported -- and only a caller who KEPT that receipt can
 *     detect a truncation. Storing the receipt is the caller's job, and this says so rather than
 *     implying the file is complete.
 *   * **Who wrote it.** Nothing here signs. Anyone holding the passphrase can append, and anyone at
 *     all can append to a chain they cannot read. The record shows that a sequence was not altered
 *     after the fact; it does not establish authorship.
 *   * **The passphrase.** It is not stored, derived or recoverable. Lose it and the payloads are
 *     gone; that is the design, not a gap.
 *   * **Deletion of the whole file.** Trivially possible, and indistinguishable from a vault that
 *     was never written. Only an off-machine copy addresses that.
 */
import fs from "node:fs";
import path from "node:path";
import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export const VAULT_SCHEMA = "aikawamei-vault/1";
export const VAULT_CIPHER = "aes-256-gcm";
export const VAULT_KDF = "scrypt";
export const GENESIS = null;

const KEY_BYTES = 32;
const SALT_BYTES = 16;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

/**
 * scrypt cost. Recorded in every envelope rather than assumed, so an opener uses the parameters the
 * sealer actually used -- and a suite can seal cheaply without the production cost being softened
 * for everyone. Default is ~32 MB of memory per derivation.
 */
export const VAULT_COST = Object.freeze({ n: 1 << 15, r: 8, p: 1 });

function costOf(cost) {
  const c = cost ?? VAULT_COST;
  return { n: c.n, r: c.r, p: c.p };
}

/** The key for one envelope. Derived per-salt, never stored. */
export function deriveKey(passphrase, saltHex, cost) {
  const c = costOf(cost);
  // The bound OpenSSL actually enforces is NOT the 128*N*r the Node documentation describes: asking
  // for n=1024 with a 2 MB ceiling is refused, and the same derivation is accepted at 16 MB. Rather
  // than reverse-engineer the real formula, the ceiling is set with a floor well above every cost
  // this module offers, and both ends of the range are exercised by the suite.
  const maxmem = Math.max(32 * 1024 * 1024, 128 * c.n * c.r * 4);
  return scryptSync(Buffer.from(String(passphrase), "utf8"), Buffer.from(saltHex, "hex"), KEY_BYTES, { ...c, maxmem });
}

/**
 * Seal one value. Returns a self-describing envelope: an opener needs the passphrase and nothing
 * else, and cannot be misled about which algorithm or parameters were used.
 */
export function sealValue(passphrase, value, { cost = null } = {}) {
  const c = costOf(cost);
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const key = deriveKey(passphrase, salt.toString("hex"), c);
  const cipher = createCipheriv(VAULT_CIPHER, key, nonce);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    format: VAULT_SCHEMA,
    cipher: VAULT_CIPHER,
    kdf: VAULT_KDF,
    kdf_params: c,
    salt: salt.toString("hex"),
    nonce: nonce.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    payload: body.toString("base64"),
  };
}

/** Open one envelope. A wrong passphrase fails the GCM tag rather than returning anything. */
export function openValue(passphrase, envelope) {
  if (!isEnvelope(envelope)) throw new Error("not a vault envelope");
  const key = deriveKey(passphrase, envelope.salt, envelope.kdf_params);
  const decipher = createDecipheriv(VAULT_CIPHER, key, Buffer.from(envelope.nonce, "hex"));
  decipher.setAuthTag(Buffer.from(envelope.tag, "hex"));
  const out = Buffer.concat([decipher.update(Buffer.from(envelope.payload, "base64")), decipher.final()]);
  return JSON.parse(out.toString("utf8"));
}

/** Structural check only: what the envelope claims to be, not whether it opens. */
export function isEnvelope(v) {
  return !!v && typeof v === "object"
    && v.format === VAULT_SCHEMA && v.cipher === VAULT_CIPHER && v.kdf === VAULT_KDF
    && typeof v.salt === "string" && typeof v.nonce === "string" && typeof v.tag === "string"
    && typeof v.payload === "string"
    && v.salt.length === SALT_BYTES * 2 && v.nonce.length === NONCE_BYTES * 2 && v.tag.length === TAG_BYTES * 2;
}

/** The digest of one raw line. This is what the next record points at. */
export function lineHash(line) {
  return createHash("sha256").update(String(line), "utf8").digest("hex");
}

/**
 * Build one record. `prev` is the hash of the previous LINE, and it is what makes the file a chain
 * rather than a list: editing any line changes its hash, and the next record no longer matches it.
 */
export function makeRecord({ prev = GENESIS, at = null, kind = null, sealed = null, note = null } = {}) {
  const record = { schema: VAULT_SCHEMA, at: at ?? new Date().toISOString(), prev, kind, note, sealed };
  const line = JSON.stringify(record);
  return { record, line, hash: lineHash(line) };
}

/** Append a record to a chain held in memory as an array of lines, returning the new array. */
export function appendTo(lines, options) {
  const arr = Array.isArray(lines) ? lines.slice() : [];
  const prev = arr.length ? lineHash(arr[arr.length - 1]) : GENESIS;
  const { line, hash } = makeRecord({ ...options, prev });
  arr.push(line);
  return { lines: arr, hash };
}

/**
 * Verify the links, and optionally the length and head a previous verification reported.
 *
 * `broken` names the FIRST index whose link does not hold, because that is the index a reader has to
 * look at; later records are usually collateral. A blank line is a removal, not a separator.
 */
export function verifyChain(lines, { expectLength = null, expectHead = null } = {}) {
  const arr = Array.isArray(lines) ? lines : [];
  const result = { ok: true, length: arr.length, head: arr.length ? lineHash(arr[arr.length - 1]) : null, broken: null, truncation_detected: false };

  for (let i = 0; i < arr.length; i += 1) {
    if (typeof arr[i] !== "string" || arr[i].trim() === "") {
      result.ok = false;
      result.broken = { index: i, reason: "blank line where a record should be" };
      return result;
    }
    let rec;
    try { rec = JSON.parse(arr[i]); } catch { result.ok = false; result.broken = { index: i, reason: "not valid JSON" }; return result; }
    const want = i === 0 ? GENESIS : lineHash(arr[i - 1]);
    if ((rec.prev ?? null) !== want) {
      result.ok = false;
      result.broken = { index: i, reason: i === 0 ? "first record does not start the chain" : "does not link to the record before it" };
      return result;
    }
  }

  // Only a kept receipt can see a tail that was cut: the remaining links are all intact.
  if (Number.isInteger(expectLength) && arr.length < expectLength) {
    result.ok = false;
    result.truncation_detected = true;
    result.broken = { index: arr.length, reason: `the record is shorter than the last receipt reported (${arr.length} of ${expectLength})` };
    return result;
  }
  if (typeof expectHead === "string" && expectHead && result.head !== expectHead) {
    result.ok = false;
    result.truncation_detected = true;
    result.broken = { index: arr.length - 1, reason: "the head is not the one the last receipt reported" };
  }
  return result;
}

/** Split a vault file into lines, tolerating a trailing newline but NOT blank interior lines. */
export function linesOf(text) {
  const raw = String(text ?? "").split("\n");
  while (raw.length && raw[raw.length - 1] === "") raw.pop();
  return raw;
}

/* ------------------------------------------------------------------ the file
 *
 * Appending reads the chain to find the previous line, then appends ONE line. It does not rewrite
 * the file, so an interrupted append leaves a complete record followed by nothing rather than a
 * half-written file -- the failure mode a read-modify-write would have.
 *
 * SINGLE WRITER is assumed and not enforced. Two processes appending at the same moment both read
 * the same tail and both chain onto it, which forks the chain: verification then reports the second
 * of the two as broken, which is true but not a diagnosis. A lock is deliberately not added here --
 * this module is a mechanism, and a mechanism that silently takes locks is worse than one that says
 * what it assumes.
 */

/** The chain as lines, or null when the file does not exist. A missing file is not an error. */
export function readChain(file) {
  try {
    return linesOf(fs.readFileSync(file, "utf8"));
  } catch (e) {
    if (e && e.code === "ENOENT") return null;
    throw e;
  }
}

/** Append one record. Creates the file, and its directory, when they are absent. */
export function appendRecord(file, options = {}) {
  const lines = readChain(file) ?? [];
  const { lines: next, hash } = appendTo(lines, options);
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.appendFileSync(file, next[next.length - 1] + "\n", "utf8");
  return { hash, length: next.length };
}

/** Verify a chain on disk, including against a receipt a previous verification reported. */
export function verifyFile(file, expectations = {}) {
  const lines = readChain(file);
  if (lines === null) return { ok: false, length: 0, head: null, broken: { index: 0, reason: "no record at that path" }, truncation_detected: false, exists: false };
  return { ...verifyChain(lines, expectations), exists: true };
}

/** Compare two digests without leaking where they differ. */
export function digestsEqual(a, b) {
  const x = Buffer.from(String(a ?? ""), "utf8");
  const y = Buffer.from(String(b ?? ""), "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}
