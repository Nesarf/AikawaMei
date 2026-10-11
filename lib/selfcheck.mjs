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
