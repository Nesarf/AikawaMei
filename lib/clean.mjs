/**
 * AikawaMei - removal
 *
 * THE ONLY PART OF THIS PROJECT THAT LEAVES FEWER FILES THAN IT FOUND
 * -------------------------------------------------------------------
 * Collection copies, the vault appends, the self-check writes a manifest. Each of those leaves the
 * original alone. A deletion does not, and it is the only operation here that cannot be checked
 * afterwards by reading something -- the evidence is the absence, and absence looks the same as
 * "there was never anything there".
 *
 * So this file does three things instead of one:
 *
 *   1. It never decides what may be removed. That list is data (`REMOVABLE` in checks.mjs), keyed by
 *      check id, and a finding whose id is not in it is reported and left alone. The set of files
 *      holding saved credentials is excluded there, deliberately and permanently.
 *
 *   2. It builds a plan that can be read and refused. Every entry carries the path, the size it had
 *      when the audit saw it, and what removing it costs. Nothing is touched until `apply` is asked
 *      for, and the API is shaped so "ask first" is the default rather than a flag to remember.
 *
 *   3. It re-checks the file immediately before removing it. A size that changed since the audit
 *      means the application wrote to it in between, and the plan describes a file that no longer
 *      exists. That is refused and reported, because the alternative is removing a file whose
 *      contents nobody described.
 *
 * The filesystem is injected rather than imported. That keeps the planning side a pure function of
 * (findings, table) and lets a test drive every branch -- including the refusal ones -- without a
 * real file to destroy.
 */
import { REMOVABLE } from "./checks.mjs";

export const CLEAN_SCHEMA = "aikawamei-clean/1";

/**
 * What a removal run is allowed to touch, derived from a set of findings.
 *
 * Returns the plan and, separately, the findings that carry a path but were NOT planned -- the
 * second list is the interesting one: it is where "there is a file here, and this tool will not
 * delete it" gets said out loud instead of silently omitted.
 */
export function planClean(findings = [], removable = REMOVABLE) {
  const planned = [];
  const kept = [];
  const seen = new Set();

  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || typeof f.id !== "string") continue;
    const abs = f.evidence && typeof f.evidence.abs === "string" ? f.evidence.abs : null;
    if (!abs) continue;

    const cost = removable[f.id];
    if (typeof cost !== "string") {
      // A path with no entry in the table. Reported so the omission is visible: a reader who sees
      // logins.json in this list learns more than one who never sees it mentioned.
      kept.push({ id: f.id, path: abs, layer: f.layer ?? null, severity: f.severity ?? null });
      continue;
    }
    // One path, one entry. `state-file` and a cache can never share a path, but a catalog edit
    // later could make two checks read the same file, and a plan that lists a file twice is a plan
    // that removes it twice and reports a failure on the second try.
    if (seen.has(abs)) continue;
    seen.add(abs);

    const size = typeof f.evidence.size === "number" ? f.evidence.size : null;
    const mtime = typeof f.evidence.mtime === "string" ? f.evidence.mtime : null;
    planned.push({ id: f.id, path: abs, bytes: size, mtime, layer: f.layer ?? null, severity: f.severity ?? null, cost });
  }

  const total = planned.reduce((n, p) => n + (typeof p.bytes === "number" ? p.bytes : 0), 0);
  return { planned, kept, total_bytes: total };
}

/**
 * Carry out a plan.
 *
 * `io` is `{ statOf(path) -> {size,mtime}|null, unlink(path) }`; both are required, so a caller
 * cannot half-implement this and get a silent no-op that reports success.
 *
 * Each entry is re-statted. A file that is gone is not an error (the plan is stale, not wrong); a
 * file whose size changed is refused, because the audit described different bytes.
 */
export function applyClean(plan, io) {
  if (!io || typeof io.statOf !== "function" || typeof io.unlink !== "function") {
    throw new TypeError("applyClean needs io.statOf and io.unlink; a removal run that cannot read or delete must not report success");
  }
  const removed = [];
  const gone = [];
  const refused = [];

  for (const p of plan?.planned ?? []) {
    const st = io.statOf(p.path);
    if (!st) { gone.push({ id: p.id, path: p.path, why: "already absent when the plan ran" }); continue; }
    if (typeof p.bytes === "number" && st.size !== p.bytes) {
      refused.push({
        id: p.id, path: p.path,
        why: `size changed since the audit (${p.bytes} then, ${st.size} now) - the plan describes different bytes`,
      });
      continue;
    }
    try {
      io.unlink(p.path);
      removed.push({ id: p.id, path: p.path, bytes: p.bytes ?? st.size });
    } catch (e) {
      refused.push({ id: p.id, path: p.path, why: String((e && e.message) || e) });
    }
  }

  return {
    removed, gone, refused,
    freed_bytes: removed.reduce((n, r) => n + (typeof r.bytes === "number" ? r.bytes : 0), 0),
  };
}
