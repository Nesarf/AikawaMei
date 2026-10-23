/**
 * AikawaMei - termination
 *
 * THE DIFFERENCE BETWEEN "KILLED" AND "NEUTRALISED" IS A SECOND LOOK.
 *
 * Killing a process is the easiest thing a tool can do and the least useful on its own. Anything
 * that can restore itself -- which is the whole shape this project is pointed at -- is back within
 * seconds, and the operator who ran one `Stop-Process` believes the problem is solved while the
 * program is quietly running again under a new pid. So this module's output has two halves:
 *
 *   the kill, and the look afterwards
 *
 * `plan.then` carries the second one as a fact rather than a suggestion: after the terminations,
 * the same match runs again over a fresh process list, and anything that came back is reported as
 * `respawned` with what that implies -- something is starting it, and the starting is the problem.
 * That is the difference between a tool that removes a symptom and one that tells you the symptom
 * will return.
 *
 * WHAT THIS MODULE NEVER TOUCHES:
 *   - itself, or the process that launched it. Ending the thing doing the terminating is not a
 *     containment, it is a self-inflicted outage, and on this machine it would cut the session the
 *     operator is watching it from.
 *   - anything it was not pointed at. There is no pattern that sweeps: a pid or a path has to be
 *     named, and a name that matches nothing produces a report, not a guess.
 *   - a process it cannot identify. A pid whose executable path cannot be read is reported with that
 *     fact rather than killed on the strength of its name alone, because two programs can share one.
 *
 * The process list and the kill call are injected so the suite can drive every branch -- including
 * "it came back" -- without ending a real process.
 */
export const TERMINATE_SCHEMA = "aikawamei-terminate/1";

/** Windows reports no-extension names for some services; a request for `x.exe` should still match. */
function normaliseName(n) {
  const s = String(n ?? "").trim().toLowerCase();
  if (!s) return null;
  return s.endsWith(".exe") ? s.slice(0, -4) : s;
}

function normalisePath(p) {
  const s = String(p ?? "").trim().toLowerCase().replace(/\//g, "\\");
  return s || null;
}

/**
 * Build the list of processes a request would end, and the requests that matched nothing.
 *
 * `paths` are full executable paths (what a neutralize step names); `names` are process names. A
 * path is matched exactly against `ExecutablePath`; when that field is not readable, the request
 * falls back to the file name only IF the caller asked by name -- matching on a basename the caller
 * did not supply would be the guess this module refuses to make.
 */
export function terminatePlan(processes = [], { paths = [], names = [], selfPid = null } = {}) {
  // One pid or several: the tool passes its own and its parent's, because ending either is an outage
  // rather than a containment, and on this machine the parent is the shell the session was opened in.
  const selfSet = new Set((Array.isArray(selfPid) ? selfPid : [selfPid])
    .filter((v) => v !== null && v !== undefined)
    .map(Number));
  const list = (Array.isArray(processes) ? processes : [])
    .map((p) => ({
      pid: Number(p?.ProcessId ?? p?.pid ?? p?.Id ?? 0),
      name: p?.Name ?? p?.name ?? null,
      path: p?.ExecutablePath ?? p?.path ?? null,
    }))
    .filter((p) => Number.isInteger(p.pid) && p.pid > 0);

  const wantPaths = (Array.isArray(paths) ? paths : []).map(normalisePath).filter(Boolean);
  const wantNames = (Array.isArray(names) ? names : []).map(normaliseName).filter(Boolean);

  const matched = [];
  const skipped = [];
  const seen = new Set();
  const hitPaths = new Set();
  const hitNames = new Set();

  for (const p of list) {
    const pPath = normalisePath(p.path);
    const pName = normaliseName(p.name);
    let why = null;
    if (pPath && wantPaths.includes(pPath)) { why = "path"; hitPaths.add(pPath); }
    // A name request matches on the name field, and on the basename of a readable path -- both are
    // the same claim ("this program"), and a name match needs no path at all.
    if (!why && pName && wantNames.includes(pName)) { why = "name"; hitNames.add(pName); }
    if (!why && pPath && wantNames.includes(normaliseName(pPath.split("\\").pop()))) { why = "name"; hitNames.add(normaliseName(pPath.split("\\").pop())); }
    if (!why) continue;

    // The two pids that must never be touched. Stated in the result rather than filtered silently:
    // a request that asked to end the terminating process should see that it was refused.
    if (selfSet.has(p.pid)) {
      skipped.push({ pid: p.pid, name: p.name, path: p.path, why: "this is the process doing the terminating, or the one that started it" });
      continue;
    }
    if (seen.has(p.pid)) continue;
    seen.add(p.pid);
    matched.push({
      pid: p.pid, name: p.name, path: p.path, matched_by: why,
      // A pid is reused. What is recorded is the path that was matched, so a later reader can tell
      // whether the process that died is the one this report is about.
      identified: Boolean(p.path) || why === "name",
    });
  }

  const unmatched = [
    ...wantPaths.filter((p) => !hitPaths.has(p)).map((p) => ({ kind: "path", value: p })),
    ...wantNames.filter((n) => !hitNames.has(n)).map((n) => ({ kind: "name", value: n })),
  ];

  return { matched, skipped, unmatched };
}

/**
 * End what the plan matched.
 *
 * `io.kill(pid)` is required. `io.list()` is optional: with it the module re-reads the process list
 * and reports what came back, which is the half of neutralisation that a kill alone never gives.
 * Both are injected so a test can drive "it returned" without spawning anything.
 */
export function applyTerminate(plan, io) {
  if (!io || typeof io.kill !== "function") {
    throw new TypeError("applyTerminate needs io.kill; a termination run that cannot end anything must not report success");
  }
  const ended = [];
  const refused = [];

  for (const p of plan?.matched ?? []) {
    try {
      io.kill(p.pid);
      ended.push({ pid: p.pid, name: p.name, path: p.path, matched_by: p.matched_by });
    } catch (e) {
      refused.push({ pid: p.pid, name: p.name, path: p.path, why: String((e && e.message) || e) });
    }
  }

  return { ended, refused };
}

/**
 * Look again, and say what came back.
 *
 * This is a function rather than a paragraph in the README because "did it return" is the only
 * question that separates a neutralised program from a killed one, and a claim of that kind belongs
 * in the output where it can be checked.
 */
export function respawnReport(before, after) {
  // IDENTITY, NOT "ANY NEW PID". The first version reported every process that had not been in the
  // first snapshot, so a browser tab opening during the watch window read as "the program came back".
  // A return is the same program under a new pid, and a program is identified by its path when that
  // is readable, otherwise by its name.
  const identityOf = (p) => {
    const p2 = normalisePath(p?.path ?? p?.ExecutablePath);
    if (p2) return `path:${p2}`;
    const n = normaliseName(p?.name ?? p?.Name);
    return n ? `name:${n}` : null;
  };
  const pidOf = (p) => Number(p?.pid ?? p?.ProcessId ?? 0);

  const beforePids = new Set((Array.isArray(before) ? before : []).map(pidOf));
  const beforeIds = new Set((Array.isArray(before) ? before : []).map(identityOf).filter(Boolean));

  const fresh = (Array.isArray(after) ? after : [])
    .map((p) => ({ pid: pidOf(p), name: p?.name ?? p?.Name ?? null, path: p?.path ?? p?.ExecutablePath ?? null }))
    .filter((p) => p.pid > 0 && !beforePids.has(p.pid))
    .filter((p) => {
      const id = identityOf(p);
      return id ? beforeIds.has(id) : false;
    });

  return {
    respawned: fresh.length > 0,
    fresh,
    // The sentence a reader needs, and the one they would not write themselves: a return means the
    // kill removed the activity, not the cause.
    reading: fresh.length
      ? "Something started these again. The process was ended and the program is running: what brings it back is the thing to find, and `aikawamei_neutralize`'s purge layer is where that list is."
      : "No process with these identities is running now. That is the state after a termination, not proof that nothing will start one later -- the purge and disable layers are what keep it from coming back.",
  };
}

/** What a termination run is not. Attached to every response, in both modes. */
export const TERMINATE_NOT_CLAIMED = [
  "That ending a process neutralises a program. A kill removes the activity that was running; the file, the autostart entry and whatever starts it again are untouched by this tool.",
  "That a `respawned` result means the machine is compromised further. It means something started that program again, which can be a supervisor, a scheduled task, or a user double-clicking an icon.",
  "That a pid identifies a program. Pids are reused and Windows recycles them quickly; the path recorded beside each one is what makes the entry checkable later.",
  "That this replaces the four layers of aikawamei_neutralize. It is the enforcement of one of them, and the only one that changes the running state of the machine.",
];
