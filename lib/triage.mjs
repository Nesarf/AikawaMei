/**
 * AikawaMei - intrusion triage
 *
 * The question this answers is narrow and worth stating precisely: **is there a foothold on this
 * machine, and where is it.** Not "is this machine clean" -- a negative answer from a read-only pass
 * over five artefact surfaces cannot mean that, and saying so is the whole of the discipline.
 *
 * WHAT IT CAN READ, AND WHY THOSE FIVE
 * ------------------------------------
 * Everything here is a FILE READ. Nothing is executed, which is not squeamishness: the surfaces that
 * would answer the remaining questions -- Run and RunOnce keys, the service table, Amcache and
 * ShimCache -- live in registry hives that Windows holds open, and the only ways to read them are to
 * run `reg.exe`/`sc.exe` or to parse a locked hive. So they are reported as undetermined with the
 * command that answers them, in the same shape `disk-encryption` uses, rather than guessed at.
 *
 *   WER reports    %LOCALAPPDATA%\...\WER\Report*\<id>\Report.wer -- plain key=value text, UTF-16LE.
 *                  A process that ran and crashed leaves its path here. This is the surface that
 *                  caught the miner on this machine: the executable sat in a made-up folder under
 *                  %APPDATA%\Microsoft\Windows\Themes, and a crashing run left a report naming it.
 *   Prefetch       C:\Windows\Prefetch\*.pf -- the FILENAME names the executable and the mtime is its
 *                  last run. The body is XPRESS-compressed and is deliberately not decoded: the name
 *                  and the time are what a timeline needs, and decoding a format that changes between
 *                  Windows builds would be a liability for no extra answer.
 *   Startup        the two Startup folders.
 *   Scheduled      C:\Windows\System32\Tasks -- XML, UTF-16LE, with NO FILE EXTENSION. Fields are
 *     tasks        read by name with a pattern rather than with a parser, so an unusual task can be
 *                  reported with fields missing; that limit is stated rather than hidden.
 *   User-writable  executables under the locations malware is written to, because "an executable in
 *     executables  %APPDATA% that something autostarts" is the shape being looked for.
 *
 * THE CORRELATION IS THE POINT
 * ----------------------------
 * One artefact is a fact about one thing. Several kinds of artefact inside a short window is a
 * foothold being established, and that is what `clustersOf` finds -- a cluster is only interesting
 * when it spans MORE THAN ONE SOURCE, because five entries from Prefetch are five programs run.
 */
import fs from "node:fs";
import path from "node:path";

export const TRIAGE_SCHEMA = "aikawamei-triage/1";

/** The io this module reads through. Injected so a fixture can drive every branch. */
export function realTriageIo() {
  return {
    exists: (p) => fs.existsSync(p),
    statOf: (p) => {
      try { const s = fs.statSync(p); return { size: s.size, mtime: s.mtime }; } catch { return null; }
    },
    listDir: (p) => {
      try {
        return fs.readdirSync(p, { withFileTypes: true }).map((e) => ({ name: e.name, isDirectory: () => e.isDirectory() }));
      } catch { return []; }
    },
    readBytes: (p) => {
      try { return fs.readFileSync(p); } catch { return null; }
    },
  };
}

/**
 * Decode a buffer that may be UTF-16LE with a BOM.
 *
 * Not cosmetic: the scheduled-task files are UTF-16LE, so reading them as UTF-8 produces text where
 * every field name is interleaved with NUL bytes and every pattern silently fails to match -- a
 * reader that returns "no command found" for every task on the machine.
 */
export function decodeText(buf) {
  if (!buf || buf.length === 0) return "";
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.slice(2).toString("utf16le");
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    // Big-endian UTF-16: swap the pairs, then decode. Rare, but a reader that produced mojibake here
    // would fail every pattern match and look like an empty file.
    const swapped = Buffer.from(buf.slice(2));
    swapped.swap16();
    return swapped.toString("utf16le");
  }
  return buf.toString("utf8");
}

const iso = (d) => (d instanceof Date ? d.toISOString() : null);

/* ============================================================ WER */

/** Every `key=value` line, and the `Sig[n].*` pairs folded into a map. */
export function parseWer(text) {
  const fields = {};
  const sig = {};
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at <= 0) continue;
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    const m = /^Sig\[(\d+)\]\.(\w+)$/.exec(key);
    if (m) { sig[`${m[1]}.${m[2]}`] = value; continue; }
    if (!(key in fields)) fields[key] = value;
  }
  const names = Object.keys(sig).filter((k) => k.endsWith(".Name")).map((k) => sig[k]);
  const values = Object.keys(sig).filter((k) => k.endsWith(".Value")).map((k) => sig[k]);
  return { fields, sig, signature_names: names, signature_values: values };
}

export function readWerReports(io, werRoot, { maxFiles = 400, budget = null } = {}) {
  const out = [];
  if (!werRoot || !io.exists(werRoot)) return out;
  const atCeiling = () => { if (out.length >= maxFiles) { if (budget) budget.truncated = true; return true; } return false; };
  const walk = (dir, depth) => {
    if (depth > 3 || atCeiling()) return;
    for (const e of io.listDir(dir)) {
      if (atCeiling()) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory && e.isDirectory()) { walk(full, depth + 1); continue; }
      if (e.name !== "Report.wer") continue;
      const text = decodeText(io.readBytes(full));
      const parsed = parseWer(text);
      const st = io.statOf(full);
      out.push({
        at: iso(st?.mtime ?? null),
        source: "wer",
        subject: parsed.fields.AppName || parsed.fields.AppPath || "(unnamed)",
        path: parsed.fields.AppPath ?? null,
        detail: parsed.fields.EventType ? `event ${parsed.fields.EventType}` : null,
        report: full,
        signature: parsed.signature_values.slice(0, 3),
      });
    }
  };
  walk(werRoot, 0);
  return out;
}

/* ============================================================ Prefetch */

/** `FOO.EXE-1234ABCD.pf` and `FOO.EXE.pf` both name `FOO.EXE`. */
export function prefetchSubject(fileName) {
  const base = String(fileName ?? "").replace(/\.pf$/i, "");
  return base.replace(/-[0-9A-F]{8}$/i, "");
}

export function readPrefetch(io, prefetchDir, { maxFiles = 2000, budget = null } = {}) {
  const out = [];
  if (!prefetchDir || !io.exists(prefetchDir)) return out;
  for (const e of io.listDir(prefetchDir)) {
    if (out.length >= maxFiles) { if (budget) budget.truncated = true; break; }
    if (e.isDirectory && e.isDirectory()) continue;
    if (!/\.pf$/i.test(e.name)) continue;
    const full = path.join(prefetchDir, e.name);
    const st = io.statOf(full);
    out.push({
      at: iso(st?.mtime ?? null),
      source: "prefetch",
      subject: prefetchSubject(e.name),
      path: null,
      detail: st ? `${st.size} bytes` : null,
      report: full,
      signature: [],
    });
  }
  return out;
}

/* ============================================================ startup folders */

export function readStartupFolders(io, dirs) {
  const out = [];
  for (const dir of Array.isArray(dirs) ? dirs : []) {
    if (!dir || !io.exists(dir)) continue;
    for (const e of io.listDir(dir)) {
      if (e.isDirectory && e.isDirectory()) continue;
      if (/^desktop\.ini$/i.test(e.name)) continue;
      const full = path.join(dir, e.name);
      const st = io.statOf(full);
      out.push({
        at: iso(st?.mtime ?? null),
        source: "startup",
        subject: e.name,
        path: full,
        detail: "in a Startup folder",
        report: full,
        signature: [],
      });
    }
  }
  return out;
}

/* ============================================================ scheduled tasks */

/** The fields a timeline needs, read by name. A pattern, not a parser -- and it says so. */
export function parseTaskXml(text) {
  const pick = (tag) => {
    const m = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i").exec(String(text ?? ""));
    return m ? m[1].trim() : null;
  };
  const commands = [...String(text ?? "").matchAll(/<Command[^>]*>([\s\S]*?)<\/Command>/gi)].map((m) => m[1].trim());
  const args = [...String(text ?? "").matchAll(/<Arguments[^>]*>([\s\S]*?)<\/Arguments>/gi)].map((m) => m[1].trim());
  return {
    commands,
    arguments: args,
    enabled: pick("Enabled"),
    start_boundary: pick("StartBoundary"),
    user_id: pick("UserId"),
    description: pick("Description"),
  };
}

export function readScheduledTasks(io, tasksDir, { maxFiles = 600, maxDepth = 3, budget = null } = {}) {
  const out = [];
  if (!tasksDir || !io.exists(tasksDir)) return out;
  const walk = (dir, depth, rel) => {
    if (depth > maxDepth || out.length >= maxFiles) return;
    for (const e of io.listDir(dir)) {
      if (out.length >= maxFiles) { if (budget) budget.truncated = true; return; }
      const full = path.join(dir, e.name);
      const name = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory && e.isDirectory()) { walk(full, depth + 1, name); continue; }
      const st = io.statOf(full);
      const parsed = parseTaskXml(decodeText(io.readBytes(full)));
      const boundary = parsed.start_boundary ? Date.parse(parsed.start_boundary) : NaN;
      out.push({
        at: Number.isFinite(boundary) ? new Date(boundary).toISOString() : iso(st?.mtime ?? null),
        source: "task",
        subject: name,
        path: parsed.commands[0] ?? null,
        detail: [parsed.enabled === null ? null : `enabled=${parsed.enabled}`, parsed.user_id].filter(Boolean).join(" ") || null,
        report: full,
        signature: parsed.commands.slice(0, 2),
        arguments: parsed.arguments.slice(0, 1),
      });
    }
  };
  walk(tasksDir, 0, "");
  return out;
}

/* ============================================================ user-writable executables */

export function readUserWritableExecutables(io, roots, { maxDepth = 5, maxFiles = 4000, budget = null } = {}) {
  const out = [];
  const mark = () => { if (out.length >= maxFiles && budget) budget.truncated = true; };
  const walk = (dir, depth) => {
    if (depth > maxDepth || out.length >= maxFiles) { mark(); return; }
    for (const e of io.listDir(dir)) {
      if (out.length >= maxFiles) { mark(); return; }
      const full = path.join(dir, e.name);
      if (e.isDirectory && e.isDirectory()) { walk(full, depth + 1); continue; }
      if (!/\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js)$/i.test(e.name)) continue;
      const st = io.statOf(full);
      out.push({
        at: iso(st?.mtime ?? null),
        source: "user-writable",
        subject: e.name,
        path: full,
        detail: st ? `${st.size} bytes` : null,
        report: full,
        signature: [],
      });
    }
  };
  for (const r of Array.isArray(roots) ? roots : []) if (r && io.exists(r)) walk(r, 0);
  return out;
}

/* ============================================================ the timeline */

/** Sorted by time, oldest first, with entries that carry no time last rather than dropped. */
export function timelineOf(entries) {
  const dated = [];
  const undated = [];
  for (const e of Array.isArray(entries) ? entries : []) (e && e.at ? dated : undated).push(e);
  dated.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  return [...dated, ...undated];
}

/**
 * Windows in which several artefacts appear together.
 *
 * A cluster is reported when it spans MORE THAN ONE SOURCE. Five Prefetch entries in an hour are five
 * programs that ran, which is what an hour on a working machine looks like; a task, a startup item
 * and a WER report inside the same hour is three different mechanisms agreeing.
 */
export function clustersOf(timeline, { windowMs = 60 * 60 * 1000, minEntries = 3 } = {}) {
  const dated = (Array.isArray(timeline) ? timeline : []).filter((e) => e && e.at);
  const out = [];
  let bucket = [];
  const flush = () => {
    if (bucket.length >= minEntries) {
      const sources = [...new Set(bucket.map((e) => e.source))];
      if (sources.length > 1) {
        out.push({
          from: bucket[0].at,
          to: bucket[bucket.length - 1].at,
          entries: bucket.length,
          sources,
          subjects: [...new Set(bucket.map((e) => e.subject))].slice(0, 8),
        });
      }
    }
    bucket = [];
  };
  for (const e of dated) {
    if (bucket.length && Date.parse(e.at) - Date.parse(bucket[0].at) > windowMs) flush();
    bucket.push(e);
  }
  flush();
  return out;
}

/* ============================================================ the judgements */

const USER_WRITABLE_HINT = /[\\/](AppData|Temp|tmp|Downloads|ProgramData|[Ww]indows[\\/]Themes)[\\/]/;

/** Is this path under a location a process can write to without elevation? */
export function looksUserWritable(p) {
  return typeof p === "string" && USER_WRITABLE_HINT.test(p);
}

/**
 * Is this path in one of the places Windows itself installs software?
 *
 * A named function rather than an inline pattern because the inline version was wrong in a way that
 * looked right: `\\\\` inside a regex literal means TWO literal backslashes, so the pattern matched
 * `C:\\Program Files\\x.exe` and not the real `C:\Program Files\x.exe` -- which inverted the filter,
 * and every crash report from a legitimate program was reported as one from outside the standard
 * directories. A character class needs one escape per position and cannot be miscounted the same way.
 */
export function isStandardProgramLocation(p) {
  return /^[a-z]:[\\/](program files( \(x86\))?|windows)[\\/]/i.test(String(p ?? ""));
}

/**
 * Findings, from the artefacts. Each one names what it saw and what it does NOT mean, because the
 * difference between "an executable is autostarted from %APPDATA%" and "you are compromised" is the
 * whole value of the report.
 */
export function findingsFor(entries) {
  const out = [];
  const list = Array.isArray(entries) ? entries : [];

  const autostartingUserWritable = list.filter((e) =>
    (e.source === "startup" || e.source === "task") && (looksUserWritable(e.path) || looksUserWritable(e.report)));
  if (autostartingUserWritable.length) {
    out.push({
      id: "triage-autostart-user-writable",
      layer: "endpoint",
      severity: "warn",
      title: `Found ${autostartingUserWritable.length} autostart entry pointing into a user-writable location`,
      detail: "Something starts automatically from a directory any process can write to. That is how a foothold survives a reboot without elevation -- and it is also how a legitimate updater works, so this is a place to look, not a verdict.",
      evidence: { entries: autostartingUserWritable.slice(0, 8).map((e) => ({ source: e.source, subject: e.subject, path: e.path, at: e.at })) },
      does_not_cover: "Whether the file is malicious, what it does, or who put it there -- nothing here is opened.",
    });
  }

  const crashedOutside = list.filter((e) => e.source === "wer" && e.path && !isStandardProgramLocation(e.path));
  if (crashedOutside.length) {
    out.push({
      id: "triage-crash-outside-program-files",
      layer: "endpoint",
      severity: "info",
      title: `Found ${crashedOutside.length} crash report naming an executable outside the standard program directories`,
      detail: "A process ran, crashed, and left its path behind. Most of these are ordinary third-party software; the reason to look is that this is the surface a crashing foothold leaves a trace on.",
      evidence: { entries: crashedOutside.slice(0, 8).map((e) => ({ subject: e.subject, path: e.path, at: e.at })) },
      does_not_cover: "Whether the crash was caused by the program or by something else, and whether the file still exists.",
    });
  }

  const clusters = clustersOf(timelineOf(list));
  if (clusters.length) {
    out.push({
      id: "triage-correlated-window",
      layer: "endpoint",
      severity: "info",
      title: `Found ${clusters.length} window(s) where several kinds of artefact appear together`,
      detail: "Several mechanisms agreeing inside one window is the closest a read-only pass gets to a foothold being established. It is also what a software update looks like, which is why each window lists its pieces rather than a conclusion.",
      evidence: { clusters: clusters.slice(0, 4) },
      does_not_cover: "What happened in the window, or whether the pieces are related to each other at all.",
    });
  }
  return out;
}

/**
 * The questions this pass cannot answer, with the command that can.
 *
 * Each of these is a registry surface. They are listed rather than attempted because reading them
 * means either running a program or parsing a hive Windows keeps locked, and "I could not look" is a
 * different answer from "there is nothing there" -- the first stays useful, the second is a lie.
 */
export const TRIAGE_NOT_READABLE = [
  {
    surface: "Run and RunOnce keys",
    why: "they live in registry hives Windows holds open; reading them needs a program to be run",
    answerable_by: 'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"   (and the HKLM path, and ...\\RunOnce)',
  },
  {
    surface: "the service table",
    why: "same, and a service's configuration is not mirrored to a file",
    answerable_by: "Get-Service | Where-Object { $_.StartType -eq 'Automatic' }   or   sc query state= all",
  },
  {
    surface: "Amcache and ShimCache",
    why: "Amcache is a locked hive; ShimCache is in the registry and has no file form",
    answerable_by: "AmcacheParser / AppCompatCacheParser, run against a copy of the hive",
  },
  {
    surface: "Defender's detection history and quarantine",
    why: "the history is a binary store the engine reads, and its files resist being read by anything else",
    answerable_by: "Get-MpThreatDetection   and   Get-MpThreat   (PowerShell, as an administrator)",
  },
];
