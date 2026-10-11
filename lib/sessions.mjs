/**
 * Automation session hygiene: what the browser-automation toolchains left on this machine.
 *
 * WHY THIS EXISTS
 * ---------------
 * Playwright, Selenium, Puppeteer, DrissionPage and Appium all persist the thing that makes an
 * automated session work -- cookies, localStorage, bearer tokens -- and the HTTP traffic that
 * carries them. Some of it is plaintext by design: a Playwright storage state, a Netscape-style
 * cookie jar, a HAR. The rest is a browser profile directory, which is a credential store: the
 * cookies are encrypted with a key that sits in the same directory, so anything running as that
 * user can read them.
 *
 * The tool exists because none of the five frameworks reports it. Each writes the file it needs and
 * says nothing about where it went, whether it is inside a repository, or what a copy is worth.
 *
 * STATIC, READ-ONLY, AND THE LIMIT THAT MATTERS
 * ---------------------------------------------
 * This reads NAMES and SIZES. It does not open a cookie jar, a storage state or a profile, and it
 * never uses the network. So it can say that a plaintext session export is sitting inside a git
 * working tree; it cannot say what is in the export, whether the session is still valid, whether
 * git ignores it, or whether it was ever committed. Where a question needs a tool this one does
 * not have, it is reported as undetermined with the command that answers it, rather than guessed
 * at -- the precedent `disk-encryption` set.
 *
 * A hardcoded path would be a fact about one machine. The roots come from the environment, and
 * whatever was actually scanned is named in the response, so a scan that covered three roots never
 * reads as though it covered four.
 */
import path from "node:path";
import { daysSince, exists, probeInputsFor } from "./shared.mjs";
import { evaluateBuiltins } from "./checks.mjs";

export const SESSIONS_SCHEMA = "aikawamei-sessions/1";

/** The base name the sessions catalog entries are written against. */
export const SESSIONS_BASE = "sessions_root";

/** How far up from a hit the walk looks for a repository root before giving up. */
const GIT_WALK_LIMIT = 64;

/**
 * The roots to scan when the caller names none.
 *
 * Derived from the environment rather than written down, because a hardcoded layout is true of one
 * machine and this tool has to be useful on someone else's. Nothing is filtered here: whether a
 * root exists is established by the scan, so an absent one is reported as absent rather than
 * silently dropping out of the list before anyone can see it was considered.
 *
 * The working directory is included on purpose. Automation scripts and the exports they produce
 * usually live in a project directory, and that is the one place a caller is most likely to be
 * standing in already.
 */
export function defaultSessionRoots(env = process.env, cwd = process.cwd()) {
  return [
    env.USERPROFILE || env.HOME || null,
    env.APPDATA || null,
    env.LOCALAPPDATA || null,
    env.TEMP || env.TMP || null,
    cwd || null,
  ].filter((r) => typeof r === "string" && r.length > 0);
}

/**
 * Order the roots and drop the ones already covered by an earlier one.
 *
 * Overlapping roots are the normal case, not an error: a home directory contains the app-data
 * directories, and a caller who passes both means "here and here", not "count it twice". A root
 * lying inside one already being scanned is skipped and NAMED, so the response can state what it
 * did not scan instead of quietly double-counting the same file under two headings.
 */
export function planSessionRoots(roots) {
  const scanned = [];
  const skipped = [];
  for (const raw of Array.isArray(roots) ? roots : []) {
    if (typeof raw !== "string" || !raw) continue;
    const abs = path.resolve(raw);
    if (scanned.includes(abs)) continue;
    const coveredBy = scanned.find((s) => abs === s || abs.startsWith(s + path.sep));
    if (coveredBy) {
      skipped.push({ root: abs, covered_by: coveredBy });
      continue;
    }
    scanned.push(abs);
  }
  return { scanned, skipped };
}

/** The probe context for one root. `io` is only for tests; the probe's own io is the real one. */
export function sessionsProbeContext(root, io = null) {
  const ctx = probeInputsFor(root, { [SESSIONS_BASE]: root });
  if (io) ctx.io = { ...ctx.io, ...io };
  return ctx;
}

/**
 * Every sessions finding for one root, in catalog order.
 *
 * `io` is threaded through rather than captured so that the whole scan -- not just the annotation
 * after it -- can be driven by a fake filesystem. Two of the behaviours worth asserting live on
 * branches a real fixture cannot cheaply reach: a walk that hits its entry budget, and a walk that
 * stops at its depth bound. Building twenty thousand files on disk to reach the first would make
 * the suite slow enough that it would eventually be skipped, which is how a bound stops being
 * tested at all.
 */
export function sessionsFindings(root, io = null) {
  if (typeof root !== "string" || !root) return [];
  return evaluateBuiltins("sessions", sessionsProbeContext(root, io));
}

/**
 * The nearest directory at or above `startDir` holding a `.git` entry, or null.
 *
 * Presence only, and deliberately so. `.git` is a directory in an ordinary clone and a FILE in a
 * linked worktree or a submodule, so both are accepted. Nothing under it is read: the question
 * answered here is "is this file inside a working tree", which is not the same question as "is it
 * tracked" or "is it ignored" -- those need git, and are reported as undetermined instead.
 */
export function gitWorktreeRootOf(startDir, io = { exists }) {
  let dir = startDir;
  for (let i = 0; i < GIT_WALK_LIMIT && dir; i += 1) {
    if (io.exists(path.join(dir, ".git"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/**
 * Add the two facts about a hit that a catalog entry cannot express: its age, and whether it sits
 * inside a working tree.
 *
 * Both are annotated here rather than computed inside the probe because the probe vocabulary is
 * kept small on purpose, and because these are facts ABOUT a hit rather than another shape of
 * check -- a name match cannot walk upward, and `mtime` is a timestamp rather than an age. Age is
 * carried the same way `path-residue` carries it, so the two targets answer "how old" identically.
 *
 * `now` is injected for the same reason it is injected into `daysSince`: an age assertion that has
 * to allow a day either side of the expected value is not an assertion.
 */
export function annotateHits(findings, io = { exists }, now = Date.now()) {
  for (const f of findings) {
    const root = f?.evidence?.root;
    const entries = f?.evidence?.entries;
    if (typeof root !== "string" || !Array.isArray(entries)) continue;
    for (const hit of entries) {
      const rel = String(hit.path ?? "").replace(/\/+$/, "");
      hit.git_root = gitWorktreeRootOf(path.dirname(path.join(root, rel)), io);
      hit.age_days = daysSince(hit.mtime, now);
    }
  }
  return findings;
}

/**
 * One root: scan, annotate, and report what the scan actually covered.
 *
 * `truncated` is carried up rather than left in the per-entry evidence, because a bounded walk
 * that stopped early is the single most important thing a reader of this output needs to know: a
 * clean result from a partial scan is not a clean result.
 */
export function scanSessionRoot(root, io = null) {
  const findings = annotateHits(sessionsFindings(root, io), io ?? { exists });
  const scans = findings.map((f) => f?.evidence ?? {});
  return {
    root,
    scanned_entries: scans.reduce((m, e) => Math.max(m, Number(e.scanned) || 0), 0),
    truncated: scans.some((e) => e.truncated === true),
    depth_limited: scans.some((e) => e.depth_limited === true),
    findings,
  };
}

/**
 * The questions this tool cannot answer, with the command that can.
 *
 * Stated once, in the response, rather than buried in a comment: each of these is a question a
 * reader will have on seeing the output, and answering any of them would mean either running
 * something or reading a credential store -- both of which this tool refuses to do.
 */
export const SESSIONS_NOT_DETERMINED = [
  {
    question: "Which of these paths git ignores, and which were ever committed",
    answerable_by: 'git -C <repo> check-ignore -v "<path>"   and   git -C <repo> log --all -- "<path>"',
    why_not: "Answering it means running git. This tool runs nothing: its whole read surface is names and sizes through an injected filesystem.",
  },
  {
    question: "Whether a session export still carries a valid session",
    answerable_by: "nothing static answers this, and loading the export would use the session",
    why_not: "Establishing it means presenting the cookies to the site, which is the harm being guarded against.",
  },
  {
    question: "What any of these files contain",
    answerable_by: "opening one deliberately, by hand",
    why_not: "By design. A tool that reads a credential store in order to describe it has made a copy of the credential.",
  },
];
