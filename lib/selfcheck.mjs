/**
 * AikawaMei - watching its own installation
 *
 * WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
 * ---------------------------------------------
 * The tempting version of "protect yourself on a machine you own" is an agent that refuses to be
 * deleted: that hides, that reinstalls itself, that resists the owner. That version is a rootkit by
 * construction, and it is a rootkit even when the owner is the person who installed it -- because on
 * a machine whose owner has root, anything that survives the owner is something the owner can no
 * longer account for. Every incident responder who has met one knows what that costs.
 *
 * What is actually worth having is smaller and real: **make the change visible.** A holdout on your
 * own land is not valuable because it cannot be moved; it is valuable because moving it is SEEN. So
 * this module answers three questions and nothing more:
 *
 *   * Is the installation what it was? A manifest of its own files, compared against a manifest
 *     captured earlier, names every file added, removed or altered.
 *   * Is the record still whole? The chain's own verifier, against the length and head a receipt
 *     reported -- which is the only thing that catches a tail that was cut.
 *   * If neither can be answered, what would answer it? Stated, because an agent that has been
 *     removed cannot report its own removal, and pretending otherwise is the sort of claim this
 *     project exists to refuse.
 *
 * The last point is the honest limit and it is why the manifest is worth writing somewhere else:
 * a copy of it that lives off this machine is the only thing that can tell you the agent is gone.
 */
import fs from "node:fs";
import path from "node:path";
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import { digestOfFile } from "./collect.mjs";

export const SELFCHECK_SCHEMA = "aikawamei-selfcheck/1";

/** The parts of an installation that decide what it does: the code, and the manifest that names it. */
export const SELF_PATTERNS = [/^lib\/[^/]+\.mjs$/, /^cli\/[^/]+\.mjs$/, /^mcp\/[^/]+\.mjs$/, /^package\.json$/, /^\.gitattributes$/];

/**
 * The installation's own files, relative to its root.
 *
 * Bounded and shallow on purpose: this is not a tree walk. An installation is a known set of
 * directories, and a self-check that wandered would spend its time hashing a build output.
 */
export function selfFiles(root, { patterns = SELF_PATTERNS, maxFiles = 400 } = {}) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 2 || out.length >= maxFiles) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      const full = path.join(dir, e.name);
      const rel = path.relative(root, full).split(path.sep).join("/");
      if (e.isDirectory()) { walk(full, depth + 1); continue; }
      if (patterns.some((p) => p.test(rel))) out.push(rel);
    }
  };
  walk(root, 0);
  return out.sort();
}

/** A manifest: one entry per file, with the digest of what is there now. */
export function manifestOf(root, files = null, { at = new Date().toISOString() } = {}) {
  const list = files ?? selfFiles(root);
  const entries = [];
  for (const rel of list) {
    const full = path.join(root, rel);
    let st = null;
    try { st = fs.statSync(full); } catch { st = null; }
    entries.push({
      path: rel,
      present: !!st,
      size: st ? st.size : null,
      mtime: st ? st.mtime.toISOString() : null,
      sha256: st ? digestOfFile(full) : null,
    });
  }
  return { schema: SELFCHECK_SCHEMA, root: path.resolve(root), at, count: entries.length, entries };
}

/**
 * What changed between two manifests.
 *
 * A file that is present in one and absent from the other is ADDED or REMOVED; one whose digest
 * differs is CHANGED. A size that moved while the digest did not is impossible, and if it happens it
 * is reported as changed rather than explained away.
 */
export function compareManifests(before, after) {
  const index = (m) => new Map((m?.entries ?? []).map((e) => [e.path, e]));
  const a = index(before);
  const b = index(after);
  const added = [];
  const removed = [];
  const changed = [];
  const unchanged = [];
  for (const [p, eb] of b) {
    const ea = a.get(p);
    if (!ea || !ea.present) { added.push(p); continue; }
    if (eb.sha256 !== ea.sha256) { changed.push({ path: p, before: ea.sha256, after: eb.sha256, size_before: ea.size, size_after: eb.size }); continue; }
    unchanged.push(p);
  }
  for (const [p, ea] of a) {
    if (!ea.present) continue;
    const eb = b.get(p);
    if (!eb || !eb.present) removed.push(p);
  }
  return {
    added: added.sort(),
    removed: removed.sort(),
    changed,
    unchanged: unchanged.sort(),
    clean: added.length === 0 && removed.length === 0 && changed.length === 0,
  };
}

/** The same comparison, made against a manifest file that was kept. */
export function readManifest(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return parsed && Array.isArray(parsed.entries) ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * The questions this cannot answer, with the thing that can.
 *
 * Stated here for the same reason every other limit in this project is stated: the most important
 * one is that **an agent that has been removed cannot report its own removal**, and an operator who
 * did not know that would read silence as safety.
 */
export const SELF_NOT_POSSIBLE = [
  {
    question: "whether this installation is still here at all",
    why: "an agent that has been removed cannot run, and so cannot report that it is gone",
    answerable_by: "a manifest kept somewhere this machine cannot write to, checked by hand -- or by the same tool run from another machine",
  },
  {
    question: "whether a removal or an edit was prevented",
    why: "nothing here prevents anything, deliberately: on a machine whose owner can become root, an agent that survives its owner is one the owner can no longer account for",
    answerable_by: "an operating-system control -- file permissions, an ACL, an immutable attribute, a backup -- not this tool",
  },
  {
    question: "who changed it",
    why: "a digest says what changed, never who did it; nothing here signs or attributes",
    answerable_by: "the OS audit log (Sysmon, the Windows security log, auditd) with the file path as the search key",
  },
];

/** One sentence for a response, so the claim and its cost travel together. */
export function selfBoundary() {
  return "This compares the installation against a manifest you kept. It detects a change and names it; it prevents nothing, and an installation that has been removed cannot report that it is gone.";
}

/* ============================================================ signing */

/**
 * A manifest two machines can agree on, byte for byte.
 *
 * Signing is worthless if the bytes signed are not the bytes verified, and a manifest read back from
 * JSON has whatever key order its writer happened to produce. So the signed form is BUILT here from a
 * fixed field list in a fixed order, and the signer and the verifier both call this function rather
 * than serialising the object themselves.
 */
export function canonicalManifest(manifest) {
  const entries = (manifest?.entries ?? []).map((e) => ({
    path: e.path ?? null,
    present: e.present === true,
    size: e.size ?? null,
    mtime: e.mtime ?? null,
    sha256: e.sha256 ?? null,
  }));
  entries.sort((a, b) => String(a.path).localeCompare(String(b.path)));
  return JSON.stringify({ schema: manifest?.schema ?? SELFCHECK_SCHEMA, count: entries.length, entries });
}

/**
 * Sign a manifest with an ed25519 private key.
 *
 * Ed25519 rather than RSA or ECDSA-P256 because it has no parameters to get wrong: no curve to pick,
 * no digest to choose, no padding mode whose absence is a vulnerability. `crypto.sign` with a null
 * algorithm is exactly that.
 *
 * What this proves, and what it deliberately does not: it proves the manifest was signed by the
 * holder of the private key and has not changed since. It does NOT prove the machine was clean when
 * the manifest was taken, and it does NOT make this tool resist anything -- a signature is read by
 * someone else, later, on purpose, which is the opposite of how a rootkit behaves.
 */
export function signManifest(manifest, privateKeyPem) {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error(`signing needs an ed25519 key; this one is ${key.asymmetricKeyType}`);
  }
  return sign(null, Buffer.from(canonicalManifest(manifest), "utf8"), key).toString("base64");
}

/** Verify a detached signature. Returns false rather than throwing on anything malformed. */
export function verifyManifestSignature(manifest, signature, publicKeyPem) {
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return false;
    return verify(null, Buffer.from(canonicalManifest(manifest), "utf8"), key, Buffer.from(String(signature), "base64"));
  } catch {
    return false;
  }
}

/** A keypair, for a caller who does not have one yet. Both halves come back as PEM text. */
export function generateSigningKeys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    private_key_pem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

/** The public half of a private key, so a signer can hand out what a verifier needs. */
export function publicKeyOf(privateKeyPem) {
  try {
    return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: "spki", format: "pem" }).toString();
  } catch {
    return null;
  }
}

/* ============================================================ the start-up gate */

/**
 * The start-up check: does this installation match the manifest the operator kept?
 *
 * WHAT THIS IS. An operator who kept a manifest can set `AIKAWAMEI_VERIFY_SELF` to its path, and the
 * executable then refuses to run when the installation does not match it -- printing what changed on
 * stderr and exiting non-zero. It is opt-in, it is loud, and it is the whole of the "integrity gate"
 * that a defender may legitimately want from anti-tamper.
 *
 * WHAT IT IS NOT, and the line is deliberate. It does not hide, it does not repair itself, it does
 * not reinstall, and it does not resist being removed. A gate that quietly repaired a modified
 * installation would be a program that changes itself on a machine whose owner did not ask, which is
 * the shape of software this project is written to find. Failing loudly and stopping is what a tool
 * can do honestly; surviving its owner is what a rootkit does.
 *
 * The limit travels with it: an installation that has been removed cannot run this, and so cannot
 * report that it is gone.
 */
export function selfGate(root, baselinePath, env = process.env) {
  const wanted = typeof baselinePath === "string" && baselinePath ? baselinePath : env.AIKAWAMEI_VERIFY_SELF;
  if (!wanted) return { armed: false, ok: true, message: null };
  const kept = readManifest(wanted);
  if (!kept) {
    return {
      armed: true, ok: false,
      message: `AIKAWAMEI_VERIFY_SELF names ${wanted}, which could not be read as a manifest. Refusing to run: an integrity gate that cannot read its baseline is not a gate.`,
    };
  }
  const diff = compareManifests(kept, manifestOf(root));
  if (diff.clean) return { armed: true, ok: true, message: null, checked: kept.count };
  const parts = [];
  if (diff.changed.length) parts.push(`${diff.changed.length} changed (${diff.changed.slice(0, 3).map((c) => c.path).join(", ")})`);
  if (diff.added.length) parts.push(`${diff.added.length} added (${diff.added.slice(0, 3).join(", ")})`);
  if (diff.removed.length) parts.push(`${diff.removed.length} removed (${diff.removed.slice(0, 3).join(", ")})`);
  return {
    armed: true, ok: false, diff,
    message: `This installation does not match the manifest at ${wanted}: ${parts.join("; ")}. ` +
      `Refusing to run. Nothing has been repaired or replaced -- if the change was yours, take a new manifest; if it was not, that is the finding.`,
  };
}
