/**
 * AikawaMei - the scope guard
 *
 * WHY THIS EXISTS
 * ---------------
 * A tool that can be pointed at a directory will eventually be pointed at one that is not the
 * operator's: another user's profile on a shared machine, a mounted volume, a network share. Nothing
 * in a file path says who owns it, and no amount of reading can establish it. So this module does the
 * two things that ARE possible:
 *
 *   * It REFUSES the shapes that most often mean someone else's data, by default and without being
 *     asked -- a UNC path, or a profile directory belonging to a different user.
 *   * When the operator DECLARES a scope, it becomes an allowlist and everything outside it is
 *     refused. An empty declaration refuses everything, because fail-closed is the only safe reading
 *     of "I own this much".
 *
 * WHAT IT DOES NOT DO, STATED HERE BECAUSE THE RESPONSE SAYS IT TOO
 * -----------------------------------------------------------------
 *   * **It cannot verify ownership.** A declaration is a claim by the operator. This module can
 *     require the claim, keep it checkable and record it; it cannot check it.
 *   * **The default rules are not a boundary.** They recognise two shapes that usually mean someone
 *     else's data. They do not recognise a borrowed laptop, a colleague's home directory mounted at
 *     an unusual path, or a share mapped to a drive letter. The default is a guard against the
 *     obvious case, and calling it more than that would be the kind of overclaim this project's
 *     notices exist to prevent.
 *   * **Symlinks are resolved when the path exists, and BOTH forms must be inside.** A link that
 *     points out of scope is refused even though the link itself is in scope, because a guard that a
 *     link can walk around is not a guard. Where the path does not exist there is nothing to resolve
 *     and only the literal form is compared.
 */
import fs from "node:fs";
import path from "node:path";

export const SCOPE_SCHEMA = "aikawamei-scope/1";

/** The sentence every response carries, so the claim and its limit travel together. */
export const SCOPE_NOTICE =
  "A scope is a declaration by the operator, not a fact this tool can establish: nothing in a path " +
  "says who owns it. What this tool does is require the claim, refuse what falls outside it, and " +
  "record the refusals.";

/** Where a path comparison is case-insensitive, by platform default. Injectable so both can be tested. */
export function caseInsensitiveFor(platform = process.platform) {
  return platform === "win32" || platform === "darwin";
}

/** Absolute, and folded when the platform folds. Never used for display -- only for comparison. */
export function normalizeForCompare(p, { caseInsensitive = caseInsensitiveFor() } = {}) {
  const abs = path.resolve(String(p));
  return caseInsensitive ? abs.toLowerCase() : abs;
}

/**
 * Is `inner` at or under `outer`?
 *
 * Compared on a path boundary rather than by prefix, because `/a/bc` starts with `/a/b` and is not
 * inside it. That single character is the difference between a guard and a decoration.
 */
export function containsPath(outer, inner, opts = {}) {
  const o = normalizeForCompare(outer, opts);
  const i = normalizeForCompare(inner, opts);
  if (o === i) return true;
  const withSep = o.endsWith(path.sep) ? o : o + path.sep;
  return i.startsWith(withSep);
}

/** A UNC path -- `\\server\share` or `//server/share` -- but not a `\\?\` device path, which is local. */
export function isNetworkPath(p) {
  const s = String(p ?? "");
  if (!/^[\\/]{2}/.test(s)) return false;
  if (/^[\\/]{2}[.?][\\/]/.test(s)) return false;
  return true;
}

/**
 * Does this look like a profile directory belonging to a user other than the current one?
 *
 * The two conventional layouts are recognised: `<drive>:\Users\<name>` and `/home/<name>` (with
 * `/Users/<name>` for macOS). Everything else is left to the caller's declaration, because a rule
 * that guessed more would refuse legitimate work while still missing the cases it did not know.
 */
export function homeOwnerOf(target) {
  const s = String(target ?? "").replace(/\\/g, "/");
  // The `i` flag is not decoration: the conventional spellings are `Users` on Windows and macOS and
  // `home` on Linux, so a case-sensitive pattern silently recognises one of the three. The first
  // version of this omitted it, and every Windows-shaped case came back as "not a home directory".
  const m = /^(?:[a-zA-Z]:)?\/+(?:users|home)\/([^/]+)/i.exec(s);
  return m ? m[1] : null;
}

export function isOtherUsersProfile(target, env = process.env, opts = {}) {
  const { caseInsensitive = caseInsensitiveFor() } = opts;
  const me = (env.USERNAME || env.USER || "").trim();
  if (!me) return false;
  // RECOGNISED BY SHAPE, NOT BY ASKING THE PLATFORM WHAT A PATH LOOKS LIKE. The first version resolved
  // the path and then split it, which works only for the platform the path was written for: on Linux
  // `path.resolve("C:\Users\someone-else\x")` becomes `/mnt/e/AikawaMei/C:\Users\someone-else\x`, whose
  // second component is `e`, so the Windows form was invisible. Auditing a mounted Windows volume from
  // Linux is an ordinary thing to do, and a Windows path is still a Windows path when read from there.
  // Both the string as written and the resolved form are tried: a relative path can resolve into a
  // home directory, and a Windows path is recognised without being resolved at all.
  for (const candidate of [String(target), path.resolve(String(target))]) {
    const name = homeOwnerOf(candidate);
    if (!name) continue;
    return caseInsensitive ? name.toLowerCase() !== me.toLowerCase() : name !== me;
  }
  return false;
}

/** The scope used when the operator declares nothing. Rule-based, by exclusion. */
export function defaultScope(env = process.env, opts = {}) {
  return {
    mode: "default",
    source: "default",
    roots: [],
    caseInsensitive: opts.caseInsensitive ?? caseInsensitiveFor(),
    rules: ["network-path", "other-user-profile"],
  };
}

/** The scope the operator claims. An allowlist, and empty means nothing is allowed. */
export function declaredScope(list, opts = {}) {
  const roots = (Array.isArray(list) ? list : [])
    .filter((r) => typeof r === "string" && r.trim() !== "")
    .map((r) => path.resolve(r));
  return {
    mode: "declared",
    source: "declared",
    roots,
    caseInsensitive: opts.caseInsensitive ?? caseInsensitiveFor(),
    rules: ["allowlist"],
  };
}

/** A scope written as lines, for a manifest kept beside a machine's notes. `#` starts a comment. */
export function parseScopeText(text, opts = {}) {
  const list = String(text ?? "")
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, "").trim())
    .filter((line) => line !== "");
  return declaredScope(list, opts);
}

/** The real path when it exists, or null. Used so a link cannot walk out of scope. */
function realPathOf(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return null;
  }
}

/**
 * Decide one target. Returns the answer AND the reason, because a refusal a reader cannot understand
 * is indistinguishable from a bug.
 */
export function classifyTarget(target, scope, opts = {}) {
  if (typeof target !== "string" || target.trim() === "") {
    return { target, allowed: false, reason: "no path was given" };
  }
  const caseInsensitive = scope?.caseInsensitive ?? caseInsensitiveFor();
  const cmp = { caseInsensitive };
  const literal = path.resolve(target);
  const real = scope?.mode === "default" ? realPathOf(literal) : realPathOf(literal);
  const forms = real && real !== literal ? [literal, real] : [literal];

  if (scope?.mode === "declared") {
    for (const form of forms) {
      const hit = (scope.roots ?? []).find((root) => containsPath(root, form, cmp));
      if (!hit) {
        return {
          target: literal,
          allowed: false,
          reason: real && real !== literal
            ? `resolves to ${real}, which is outside every declared root`
            : "outside every declared root",
        };
      }
    }
    return { target: literal, allowed: true, matchedBy: (scope.roots ?? []).find((root) => containsPath(root, literal, cmp)) ?? null };
  }

  // The RAW string is classified alongside the resolved ones, and that is not a nicety. On POSIX
  // `path.resolve("//server/share/x")` collapses the leading double slash to one, so the only form
  // that still LOOKS like a network path is the one the caller typed; on Windows the same call keeps
  // the UNC prefix, which is exactly why this went unnoticed until the suite ran on Linux. A guard
  // that normalises before it classifies destroys the signal it needs to classify on.
  for (const form of [target, ...forms]) {
    if (isNetworkPath(form)) return { target: literal, allowed: false, reason: "a network path, which is not this machine's data" };
    if (isOtherUsersProfile(form, opts.env ?? process.env, cmp)) {
      return { target: literal, allowed: false, reason: "a profile directory belonging to a different user" };
    }
  }
  return { target: literal, allowed: true, matchedBy: null };
}

/** Split a list of targets into what will be read and what will not. */
export function classifyTargets(targets, scope, opts = {}) {
  const allowed = [];
  const refused = [];
  for (const t of Array.isArray(targets) ? targets : []) {
    const r = classifyTarget(t, scope, opts);
    if (r.allowed) allowed.push(t);
    else refused.push({ target: r.target, reason: r.reason });
  }
  return { allowed, refused };
}

/** The scope, as the response reports it: checkable, and explicit about what it is not. */
export function scopeReport(scope) {
  return {
    schema: SCOPE_SCHEMA,
    mode: scope?.mode ?? "default",
    source: scope?.source ?? "default",
    declared_roots: scope?.mode === "declared" ? (scope.roots ?? []) : [],
    rules: scope?.rules ?? [],
    comparison: (scope?.caseInsensitive ?? caseInsensitiveFor()) ? "case-insensitive" : "case-sensitive",
    verified: false,
    notice: SCOPE_NOTICE,
  };
}
