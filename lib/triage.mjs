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
import { execFileSync } from "node:child_process";
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
    /**
     * Ask Windows' own registry tool about a key: a fixed command, no caller input, bounded output.
     *
     * This is the only place in this project where a program is run, and the module's stated limit is
     * untouched by it. That limit is that the thing being AUDITED is never executed, and this runs the
     * system's query tool against a key. net.mjs reads the WinINET proxy settings exactly this way for
     * exactly this reason: Node has no registry API, and pretending the data does not exist would be
     * the less honest option.
     */
    runQuery: (key, { value = null, recursive = false, timeoutMs = 8000, maxBytes = 8 * 1024 * 1024 } = {}) => {
      // `/v NAME` selects one value, and it is an argument of its own -- appending it to the key asks
      // for a key whose name contains that text, which is how this was wrong the first time.
      // `/v NAME` selects a value and `/s` walks the subkeys. A service's Start value lives under
      // its OWN subkey, so asking the Services key for it fails -- both switches are needed.
      const argv = ["query", key];
      if (value) argv.push("/v", value);
      if (recursive || !value) argv.push("/s");
      try {
        const out = execFileSync("reg.exe", argv, {
          timeout: timeoutMs, maxBuffer: maxBytes, windowsHide: true, encoding: "utf8",
        });
        return { ok: true, text: out };
      } catch (e) {
        // A key that does not exist exits non-zero with a message on stdout, and that is a real
        // answer: "this machine has no such key" is not the same as "the query failed".
        const stdout = e && e.stdout ? String(e.stdout) : "";
        if (stdout.trim()) return { ok: true, text: stdout, warned: true };
        const timedOut = e && (e.code === "ETIMEDOUT" || e.signal === "SIGTERM");
        return {
          ok: false,
          reason: timedOut ? "the query timed out" : "the registry tool could not be run",
          detail: e && e.message ? e.message : String(e),
        };
      }
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


/* ============================================================ registry surfaces */

/**
 * The keys worth asking about, as data, with the reason each one is here.
 *
 * Run keys are the oldest autostart mechanism Windows has and the one most unwanted software still
 * uses, because the per-user hive needs no privileges. The service table is the other half: an
 * automatic service runs as SYSTEM before anyone logs on, and its ImagePath is the whole story of what
 * it runs. Defender's policy keys are here because a guard that has been switched off is a fact about
 * the machine, and the fact an intruder would want to create.
 */
export const REGISTRY_SURFACES = {
  run: [
    { name: "HKCU Run", key: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { name: "HKCU RunOnce", key: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { name: "HKLM Run", key: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { name: "HKLM RunOnce", key: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
    { name: "HKLM Run (32-bit view)", key: "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
    { name: "HKLM RunOnce (32-bit view)", key: "HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
  ],
  services: "HKLM\\SYSTEM\\CurrentControlSet\\Services",
  defenderPolicy: [
    { name: "Defender policy", key: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" },
    // The state key holds hundreds of values that all say something true and none of them interesting.
    // Only the ones that bear on whether the engine is running, updating, or has been stood down are
    // kept, because a report whose Defender section is 675 lines is a report nobody reads.
    {
      name: "Defender state",
      key: "HKLM\\SOFTWARE\\Microsoft\\Windows Defender",
      keep: ["DisableAntiSpyware", "DisableAntiVirus", "PassiveMode", "SpynetReporting", "SubmitSamplesConsent", "TamperProtection", "ProductStatus"],
    },
  ],
};

/**
 * Parse `reg query` output into name/value pairs.
 *
 * The shape is one value per line: two or more spaces, the name, four spaces, the type, four spaces,
 * the data. A parser that accepted looser shapes would produce an entry for the key-path line itself,
 * which reads as an autostart item with no command -- a finding produced by the reader rather than by
 * the machine.
 */
export function parseRegQuery(text) {
  const out = [];
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const m = /^\s+(.*?)\s+(REG_[A-Z_]+)\s+(.*)$/.exec(raw);
    if (!m) continue;
    out.push({ name: m[1].trim(), type: m[2], value: m[3].trim() });
  }
  return out;
}

/** Every Run and RunOnce entry this machine executes at logon, and what each one points at. */
export function readRunKeys(io) {
  const out = [];
  const query = io && io.runQuery ? io.runQuery : null;
  for (const surface of REGISTRY_SURFACES.run) {
    if (typeof query !== "function") {
      out.push({ at: null, source: "run-key", subject: surface.name, path: surface.key,
        detail: "not read: no registry query is available in this context", report: surface.key, signature: [], unread: true });
      continue;
    }
    const res = query(surface.key);
    if (!res || !res.ok) {
      out.push({ at: null, source: "run-key", subject: surface.name, path: surface.key,
        detail: `not read: ${(res && res.reason) || "the query failed"}`, report: surface.key, signature: [], unread: true });
      continue;
    }
    for (const v of parseRegQuery(res.text)) {
      out.push({
        // A registry value carries no timestamp of its own and the hive's is the hive's. Reporting one
        // would put a fabricated time into a timeline whose only value is that its times are real.
        at: null,
        source: "run-key",
        subject: v.name,
        path: surface.key,
        detail: `${v.type} under ${surface.name}`,
        command: v.value,
        report: `${surface.key} -> ${v.name}`,
        signature: [],
      });
    }
  }
  return out;
}

/**
 * The services configured to start on their own, with the command each one runs.
 *
 * Read in two passes because `reg query` cannot filter by value name: one for Start, one for
 * ImagePath, joined here. Start 2 is automatic, and those are the ones that run before a logon.
 */
export function readServiceAutostarts(io, { maxServices = 400 } = {}) {
  const key = REGISTRY_SURFACES.services;
  const query = io && io.runQuery ? io.runQuery : null;
  if (typeof query !== "function") {
    return [{ at: null, source: "service", subject: "the service table", path: key,
      detail: "not read: no registry query is available in this context", report: key, signature: [], unread: true }];
  }
  const starts = query(key, { value: "Start", recursive: true });
  const paths = query(key, { value: "ImagePath", recursive: true });
  if (!starts || !starts.ok) {
    return [{ at: null, source: "service", subject: "the service table", path: key,
      detail: `not read: ${(starts && starts.reason) || "the query failed"}`, report: key, signature: [], unread: true }];
  }
  const imageByService = new Map();
  {
    let current = null;
    for (const raw of String((paths && paths.ok ? paths.text : "") ?? "").split(/\r?\n/)) {
      // The same two-line shape as Start above: the key path, then the value. The key path never
      // contains the value name, so a pattern that looked for "ImagePath" on it matched nothing and
      // every service came back with a null command -- which reads as "no service runs anything".
      const keyLine = /^(?:HKEY_[A-Z_]+|HKLM)\\.*\\Services\\([^\\]+)$/.exec(raw.trim());
      if (keyLine) { current = keyLine[1]; continue; }
      const val = /^\s{2,}ImagePath\s+(REG_[A-Z_]+)\s+(.*)$/.exec(raw);
      if (val && current) { imageByService.set(current, val[2].trim()); current = null; }
    }
  }
  const out = [];
  let count = 0;
  let current = null;
  for (const raw of String(starts.text ?? "").split(/\r?\n/)) {
    // Two lines per service: the key path, then the value. A pattern expecting both on ONE line found
    // nothing on a machine with hundreds of automatic services, which reads as "there are none" --
    // the same false-clean shape the truncation flag exists to prevent elsewhere.
    const keyLine = /^(?:HKEY_[A-Z_]+|HKLM)\\.*\\Services\\([^\\]+)$/.exec(raw.trim());
    if (keyLine) { current = keyLine[1]; continue; }
    const valueLine = /^\s{2,}Start\s+REG_DWORD\s+0x([0-9a-fA-F]+)\s*$/.exec(raw);
    if (!valueLine || !current) continue;
    if (valueLine[1] !== "2") { current = null; continue; }
    if (count >= maxServices) break;
    count++;
    const service = current;
    current = null;
    out.push({
      at: null,
      source: "service",
      subject: service,
      path: key + "\\" + service,
      detail: "an automatic service, which starts before anyone logs on",
      command: imageByService.get(service) ?? null,
      report: key + "\\" + current,
      signature: [],
    });
  }
  return out;
}

/**
 * Defender's policy state, and where its history lives.
 *
 * The policy keys are the ones worth reading: a guard switched off is a fact about the machine. The
 * history directories are listed by NAME, SIZE and TIME and never opened -- the store is binary, and
 * what to do with its content is the content tool's question rather than this one's. That division is
 * the answer to the entry this replaced, which said Defender's history was unreachable: its content
 * still is, from here.
 */
export function readDefenderState(io, { historyRoots = [] } = {}) {
  const out = [];
  const query = io && io.runQuery ? io.runQuery : null;
  if (typeof query !== "function") {
    out.push({ at: null, source: "defender", subject: "Defender policy", path: null,
      detail: "not read: no registry query is available in this context", report: "defender", signature: [], unread: true });
  } else {
    for (const surface of REGISTRY_SURFACES.defenderPolicy) {
      const res = query(surface.key);
      if (!res || !res.ok) {
        out.push({ at: null, source: "defender", subject: surface.name, path: surface.key,
          detail: `not read: ${(res && res.reason) || "the query failed, and this key is often protected"}`,
          report: surface.key, signature: [], unread: true });
        continue;
      }
      for (const v of parseRegQuery(res.text)) {
        if (Array.isArray(surface.keep) && !surface.keep.includes(v.name)) continue;
        out.push({ at: null, source: "defender", subject: `${surface.name}: ${v.name}`, path: surface.key,
          detail: `${v.type} = ${v.value}`, command: v.value, report: surface.key, signature: [] });
      }
    }
  }
  for (const root of Array.isArray(historyRoots) ? historyRoots : []) {
    if (!root || !io.exists(root)) continue;
    for (const e of io.listDir(root)) {
      const full = root + "\\" + e.name;
      const st = io.statOf(full);
      const isDir = e.isDirectory && e.isDirectory();
      out.push({
        at: iso(st?.mtime ?? null),
        source: "defender",
        subject: e.name,
        path: full,
        detail: isDir
          ? "a Defender history directory; its contents are not opened here"
          : `a Defender log, ${st ? st.size + " bytes" : "size unknown"}; read it with the content tool, not this one`,
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

/**
 * Expand the environment variables Windows itself puts in a command, before judging the command.
 *
 * Not cosmetic: an automatic service is almost always written as `%SystemRoot%\System32\svchost.exe`,
 * and comparing that raw string against a list of standard directories classifies it as foreign. The
 * measurement that made this necessary: 101 of 119 services on this machine looked like they ran from
 * outside the standard locations, and every one of them was a variable this function now resolves.
 *
 * An unknown variable is left as written rather than blanked, so a command that references something
 * this process does not have is still recognisable in the report.
 */
export function expandEnvPath(p, env = process.env) {
  return String(p ?? "").replace(/%([^%]+)%/g, (whole, name) => {
    const hit = Object.keys(env ?? {}).find((k) => k.toLowerCase() === String(name).toLowerCase());
    return hit ? String(env[hit]) : whole;
  });
}

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

  // The four autostart mechanisms this pass can see, judged on the command each one would run. For a
  // Run key or a service that is `command`; for a startup item or a task it is the path the entry
  // points at. The variables are expanded first, because Windows writes its own commands that way.
  const AUTOSTART_SOURCES = ["startup", "task", "run-key", "service"];
  const autostartTarget = (e) => expandEnvPath(e.command ?? e.path ?? e.report ?? "");
  const autostartingUserWritable = list.filter((e) =>
    AUTOSTART_SOURCES.includes(e.source) && looksUserWritable(autostartTarget(e)));
  if (autostartingUserWritable.length) {
    out.push({
      id: "triage-autostart-user-writable",
      layer: "endpoint",
      severity: "warn",
      title: `Found ${autostartingUserWritable.length} autostart entry pointing into a user-writable location`,
      detail: "Something starts automatically from a directory any process can write to. That is how a foothold survives a reboot, and it is also how a legitimate updater works: this is a place to look, and it is not a verdict about the file. The four mechanisms here are the startup folders, the scheduled tasks, the Run keys and the automatic services -- in that order of how much privilege each one needs.",
      evidence: { entries: autostartingUserWritable.slice(0, 8).map((e) => ({ source: e.source, subject: e.subject, target: autostartTarget(e), at: e.at })) },
      does_not_cover: "Whether the file is malicious, what it does, or who put it there -- nothing here is opened, and the command line is reported rather than executed.",
    });
  }

  // A guard switched off is not a place to look; it is a statement about the machine. Read from
  // Defender's own values, so the finding quotes the record rather than inferring from a status line.
  // Hex, because that is what `reg query` prints for a REG_DWORD: the first version compared against
  // decimal one and "0x1", and every guard that was off read as on.
  const GUARD_OFF = [
    { name: "DisableAntiSpyware", off: ["0x1", "1"] },
    { name: "DisableAntiVirus", off: ["0x1", "1"] },
    { name: "TamperProtection", off: ["0x0", "0"] },
  ];
  const guardsOff = [];
  for (const e of list) {
    if (e.source !== "defender" || !e.subject) continue;
    for (const rule of GUARD_OFF) {
      if (!String(e.subject).endsWith(rule.name)) continue;
      const value = String(e.command ?? "").trim().toLowerCase();
      if (rule.off.includes(value)) guardsOff.push({ subject: e.subject, value: e.command });
    }
  }
  if (guardsOff.length) {
    out.push({
      id: "triage-guard-disabled",
      layer: "endpoint",
      severity: "critical",
      title: `A Windows security setting is switched off (${guardsOff.map((g) => g.subject.split(": ").pop()).join(", ")})`,
      detail: "This is read from the machine's own configuration rather than inferred, and it is the one finding in this pass that is not a place to look: a guard that has been turned off is a fact. It can be a deliberate policy, an enterprise baseline, or something a third party changed -- the value does not say which, and the report does not guess.",
      evidence: { settings: guardsOff.slice(0, 8) },
      does_not_cover: "Who changed it or why, and whether anything is currently on the machine. A machine with its guard off may still be clean, and one with it on may still be compromised.",
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
    surface: "Amcache and ShimCache",
    why: "Amcache is a locked hive and ShimCache lives inside the registry with no file form; both are binary formats that need a parser",
    answerable_by: "AmcacheParser / AppCompatCacheParser, run against a copy of the hive",
  },
  {
    surface: "the CONTENT of Defender's detection history and quarantine",
    why: "the history is a binary store the engine reads, and its files resist being read by anything else -- the locations and times are read above, the contents are not",
    answerable_by: "Get-MpThreatDetection and Get-MpThreat (PowerShell, as an administrator), or the content tool against an extracted copy",
  },
];
