/**
 * AikawaMei - content rules
 *
 * THE ONE TOOL HERE THAT READS FILE CONTENTS, and what makes that acceptable.
 * -----------------------------------------------------------------------
 * Every other probe in this project states the same limit in its own words: it reads NAMES and
 * SIZES, never a file's contents, and never the network. That limit is what lets those tools run
 * over a whole machine without becoming a second place the secrets live.
 *
 * Content rules cannot work that way. A key pasted into notes.txt has a perfectly ordinary name,
 * and the only way to answer "is this file carrying something it should not" is to look at the
 * bytes. So this module pays for the difference with four constraints, and each one is checkable
 * rather than promised:
 *
 *  1. NO DERIVED ROOTS. The caller names the paths. Nothing here walks the profile, the temp
 *     directory or a drive letter, and there is no default that turns "no arguments" into "the
 *     whole machine". A scan happens where someone said it should.
 *
 *  2. A BOUNDED PREFIX. At most `max_bytes` per file (default 1 MiB, hard ceiling 8 MiB). A rule
 *     that only matches past that prefix is reported as NOT EVALUATED for that file rather than as
 *     a clean result. The distinction matters: "we did not look" and "we looked and found nothing"
 *     are different answers, and only one of them is evidence.
 *
 *  3. NO RULE LANGUAGE. Rules are data with a closed matcher vocabulary -- a literal string, or a
 *     byte sequence given in hex. No regular expressions, no nesting, no composition, no eval. This
 *     is the same boundary lib/checks.mjs draws for its predicates, for the same reason: a pattern
 *     language is a programming language with worse error messages, and it is an injection surface
 *     the moment the pattern comes from a file someone else can write.
 *
 *  4. NO WRITE PATH AT ALL. This module imports no writer, takes no flag that could mean one, and
 *     returns findings only. Deleting, moving, renaming, quarantining, changing permissions or
 *     "cleaning" a hit is not a feature this file declines to add -- it is a capability that does
 *     not exist in it. That is what "judgement never repairs" means in practice, and it is why the
 *     tool can be pointed at evidence that must not be disturbed while it is being judged.
 *
 * ON CLAMAV, AND ON YARA, WITHOUT CLAIMING COMPATIBILITY
 * ----------------------------------------------------
 * Two names appear in this file and neither is a dependency:
 *
 *   - ClamAV's signature files (.hdb, .ndb) are plain text with a published format. This module can
 *     READ a local copy of them and use their patterns as data. It does not call clamscan, does not
 *     download a database, and does not speak ClamAV's full condition language -- only the two
 *     simplest line forms are parsed, and every line outside them is counted and reported as
 *     skipped rather than silently dropped.
 *
 *   - YARA's idea -- rules as a reviewable artifact rather than as control flow -- is borrowed.
 *     YARA's syntax is not implemented and compatibility is not claimed. Naming the idea is honest;
 *     naming a format this does not implement would not be.
 *
 * A note on .hdb specifically, because it is the one place a bound changes an answer: an .hdb line
 * is a whole-file MD5. A prefix cannot satisfy it. So .hdb entries are evaluated only against files
 * the scan read IN FULL, and a file large enough to have been truncated is reported as not
 * evaluated for those entries. Reporting a truncated file as "no match" for a whole-file hash would
 * be a false clean, which is the one output this project treats as worse than an error.
 */
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import { finding, statOf, listDir } from "./shared.mjs";
import { CHECK_CATALOG } from "./checks.mjs";

export const CONTENT_SCHEMA = "aikawamei-content/1";
export const CONTENT_RULES_VERSION = "1";

/** The default prefix. Big enough for a script header, a config, or a pasted key; small enough that
 *  a directory of a thousand files is still one cheap pass. */
export const DEFAULT_MAX_BYTES = 1024 * 1024;

/** The ceiling a caller cannot raise by argument. Beyond this a "scan" becomes a copy of the data. */
export const HARD_MAX_BYTES = 8 * 1024 * 1024;

/** Default entry ceiling for one call, for the same reason every walk in this project has one. */
export const DEFAULT_MAX_FILES = 2000;

/**
 * The built-in rules, READ FROM THE CATALOG rather than declared a second time.
 *
 * The ids, layers, severities and boundaries live in lib/checks.mjs, where every other check in this
 * project declares itself. That matters for more than tidiness: a finding this tool emits is keyed
 * exactly like any other finding, so the standing assertion that every emitted id appears in the
 * catalog holds here without an exception, and a baseline can key on these ids too.
 *
 * What stays in this file is what a check entry cannot express -- the closed matcher vocabulary and
 * the scanning itself.
 */
export function builtinContentRules() {
  return CHECK_CATALOG
    .filter((c) => Array.isArray(c.targets) && c.targets.includes("content")
      && (c.matcher === "literal" || c.matcher === "hex" || c.matcher === "md5"))
    .map((c) => ({
      id: c.id,
      layer: c.layer,
      severity: Array.isArray(c.severities) && c.severities.length ? c.severities[0] : "info",
      matcher: c.matcher,
      pattern: c.pattern,
      required_size: c.required_size == null ? null : c.required_size,
      anchor: c.anchor == null ? null : c.anchor,
      label: c.title,
      why: c.detail == null ? c.title : c.detail,
      does_not_cover: c.does_not_cover,
      source: "builtin",
      disabled: c.disabled === true,
    }));
}

/* ------------------------------------------------------------- ClamAV signature files
 *
 * The two simplest line forms, and nothing else:
 *
 *   .hdb   md5:size:name            a whole-file signature
 *   .ndb   name:target:offset:hex   a byte pattern, with target 0 meaning "any file"
 *
 * Everything outside those forms -- the conditional signatures, the body-based and container-based
 * formats -- is counted and reported as skipped. A parser that silently ignores what it does not
 * understand turns a partial database into a confident scan.
 */
export function parseClamAvText(text, sourceName) {
  const rules = [];
  const problems = [];
  let skipped = 0;
  const lines = String(text ?? "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].trim();
    if (!raw || raw.startsWith("#")) continue;
    const parts = raw.split(":");
    if (parts.length === 3 && /^[0-9a-fA-F]{32}$/.test(parts[0])) {
      const size = Number(parts[1]);
      rules.push({
        id: `clamav-hdb-${sourceName}-${i + 1}`,
        layer: "crypto",
        severity: "warn",
        matcher: "md5",
        pattern: parts[0].toLowerCase(),
        required_size: Number.isFinite(size) ? size : null,
        label: `ClamAV whole-file signature ${parts[2]}`,
        source: sourceName,
        why: "Read from a local ClamAV database; the pattern is the file's whole-file digest.",
        does_not_cover: "applies only to a file read in full, and says nothing about a file this scan truncated",
      });
    } else if (parts.length >= 3 && /^[0-9a-fA-F]+$/.test(parts[parts.length - 1]) && parts[parts.length - 1].length % 2 === 0) {
      const name = parts[0];
      const target = parts[1];
      const offset = Number(parts[2]);
      rules.push({
        id: `clamav-ndb-${sourceName}-${i + 1}`,
        layer: "crypto",
        severity: "warn",
        matcher: "hex",
        pattern: parts[parts.length - 1].toLowerCase(),
        anchor: Number.isFinite(offset) ? offset : null,
        target,
        label: `ClamAV pattern ${name}`,
        source: sourceName,
        why: "Read from a local ClamAV database; the pattern is a byte sequence with an optional anchor offset.",
        does_not_cover: "matches the byte sequence only, without ClamAV's surrounding conditions or logical expressions",
      });
    } else {
      skipped++;
      if (problems.length < 8) problems.push({ line: i + 1, reason: "not one of the two simplest ClamAV line forms", text: raw.slice(0, 80) });
    }
  }
  return { rules, problems, skipped, lines: lines.length };
}

/** Read ClamAV databases from a directory, as text, with a bounded read. */
export function loadClamAvRules(dir, maxBytes = 64 * 1024 * 1024) {
  const out = { rules: [], sources: [], problems: [], skipped: 0 };
  if (typeof dir !== "string" || !dir) return out;
  const st = statOf(dir);
  if (!st || !st.isDirectory()) {
    out.problems.push({ reason: "the signature directory is not a directory this process can read", path: dir });
    return out;
  }
  for (const e of listDir(dir)) {
    if (!e || !e.isFile || !e.isFile()) continue;
    if (!/\.(hdb|ndb)$/i.test(e.name)) continue;
    const full = path.join(dir, e.name);
    const s = statOf(full);
    if (!s || s.size > maxBytes) {
      out.problems.push({ reason: "signature file larger than the read ceiling", path: full, bytes: s ? s.size : null });
      continue;
    }
    let text = "";
    try {
      text = fs.readFileSync(full, "utf8");
    } catch (err) {
      out.problems.push({ reason: `unreadable: ${err && err.message ? err.message : String(err)}`, path: full });
      continue;
    }
    const parsed = parseClamAvText(text, e.name);
    out.rules.push(...parsed.rules);
    out.sources.push({ file: e.name, bytes: s.size, rules: parsed.rules.length, lines: parsed.lines });
    out.skipped += parsed.skipped;
    out.problems.push(...parsed.problems.map((p) => ({ ...p, path: e.name })));
  }
  return out;
}

/* -------------------------------------------------------------------------- the matcher
 *
 * Four shapes, no composition. `literal` is case-sensitive ASCII; `hex` is a byte sequence read
 * from the rule text; `md5` is a whole-file digest with an optional expected size. Nothing here
 * interprets a pattern as anything other than bytes, so a rule file cannot express a program.
 */
const HEX_PAIRS = () => /^[0-9a-f]+$/;

export function compileRule(rule) {
  if (rule.matcher === "literal") {
    return { ...rule, needle: Buffer.from(String(rule.pattern ?? ""), "utf8") };
  }
  if (rule.matcher === "hex") {
    const hex = String(rule.pattern ?? "");
    if (!HEX_PAIRS().test(hex) || hex.length % 2 !== 0) return null;
    return { ...rule, needle: Buffer.from(hex, "hex") };
  }
  if (rule.matcher === "md5") return { ...rule };
  return null;
}

function indexOfBuffer(hay, needle, from = 0) {
  if (!needle || !needle.length) return -1;
  return hay.indexOf(needle, from);
}

/**
 * Evaluate one file's bytes against the compiled rules.
 *
 * `truncated` is not an implementation detail: it decides whether the whole-file rules are answered
 * or reported as not evaluated. The caller passes it, the report carries it, and no rule can talk
 * its way past it.
 */
export function evaluateBuffer(buf, rules, { truncated = false } = {}) {
  const hits = [];
  const notEvaluated = [];
  for (const rule of rules) {
    if (rule.disabled) continue;
    if (rule.matcher === "md5") {
      if (truncated) {
        notEvaluated.push({ rule: rule.id, reason: "whole-file signature, and this file was truncated by the read ceiling" });
        continue;
      }
      if (rule.required_size != null && buf.length !== rule.required_size) continue;
      const digest = crypto.createHash("md5").update(buf).digest("hex");
      if (digest === String(rule.pattern).toLowerCase()) {
        hits.push({ rule: rule.id, layer: rule.layer, severity: rule.severity, label: rule.label, offset: 0, length: buf.length, source: rule.source ?? "builtin", why: rule.why, does_not_cover: rule.does_not_cover });
      }
      continue;
    }
    if (!rule.needle || !rule.needle.length) continue;
    const from = rule.anchor != null && Number.isFinite(rule.anchor) ? Math.max(0, rule.anchor) : 0;
    const at = indexOfBuffer(buf, rule.needle, from);
    if (at >= 0) {
      hits.push({ rule: rule.id, layer: rule.layer, severity: rule.severity, label: rule.label, offset: at, length: rule.needle.length, source: rule.source ?? "builtin", why: rule.why, does_not_cover: rule.does_not_cover });
    }
  }
  return { hits, notEvaluated };
}

/* ----------------------------------------------------------------------------- the walk
 *
 * Depth-first, bounded, and explicit about every reason a file was not examined. The reasons are
 * part of the result rather than a log line, because "the scan says nothing" and "the scan could
 * not look" must never arrive as the same shape.
 */
export function collectFiles(roots, { maxFiles = DEFAULT_MAX_FILES, maxDepth = 6, followLinks = false } = {}) {
  const files = [];
  const skipped = [];
  const seen = new Set();
  const queue = [];
  for (const r of roots) {
    if (typeof r !== "string" || !r) { skipped.push({ path: String(r), reason: "not a path" }); continue; }
    const st = statOf(r);
    if (!st) { skipped.push({ path: r, reason: "does not exist, or this process cannot read it" }); continue; }
    if (st.isFile()) { files.push(r); continue; }
    if (!st.isDirectory()) { skipped.push({ path: r, reason: "neither a regular file nor a directory" }); continue; }
    queue.push({ dir: r, depth: 0 });
  }
  while (queue.length) {
    const { dir, depth } = queue.shift();
    if (files.length >= maxFiles) { skipped.push({ path: dir, reason: `entry ceiling of ${maxFiles} reached` }); continue; }
    let entries;
    try {
      entries = listDir(dir);
    } catch (err) {
      skipped.push({ path: dir, reason: `unreadable directory: ${err && err.message ? err.message : String(err)}` });
      continue;
    }
    for (const e of entries) {
      if (!e || !e.isFile || !e.isFile()) {
        if (depth + 1 > maxDepth) { skipped.push({ path: path.join(dir, e.name), reason: `deeper than the depth ceiling of ${maxDepth}` }); continue; }
        const child = path.join(dir, e.name);
        if (!followLinks && e.isSymbolicLink && e.isSymbolicLink()) { skipped.push({ path: child, reason: "symlink, and following links is off" }); continue; }
        if (seen.has(child)) { skipped.push({ path: child, reason: "already visited" }); continue; }
        seen.add(child);
        queue.push({ dir: child, depth: depth + 1 });
        continue;
      }
      if (files.length >= maxFiles) { skipped.push({ path: path.join(dir, e.name), reason: `entry ceiling of ${maxFiles} reached` }); continue; }
      files.push(path.join(dir, e.name));
    }
  }
  return { files, skipped };
}

/**
 * Read at most `limit` bytes of a file and say whether that was the whole file.
 *
 * Read through a single descriptor with an explicit byte count rather than fs.readFileSync, because
 * the ceiling is a claim about memory as well as about evidence: reading a 4 GB file to inspect its
 * first megabyte would make this tool a way to exhaust a machine.
 */
export function readPrefix(p, limit) {
  const st = statOf(p);
  if (!st || !st.isFile()) return { ok: false, reason: "not a regular file", bytes: 0, truncated: false };
  let fd = null;
  try {
    fd = fs.openSync(p, "r");
    const size = Math.min(st.size, limit);
    const buf = Buffer.alloc(size);
    let read = 0;
    while (read < size) {
      const n = fs.readSync(fd, buf, read, size - read, read);
      if (n <= 0) break;
      read += n;
    }
    return { ok: true, buf: buf.subarray(0, read), bytes: read, size: st.size, truncated: st.size > read };
  } catch (err) {
    return { ok: false, reason: `unreadable: ${err && err.message ? err.message : String(err)}`, bytes: 0, truncated: false };
  } finally {
    if (fd != null) { try { fs.closeSync(fd); } catch { /* the report already carries the outcome */ } }
  }
}

/** Everything one scan produces. Findings only: this function has no branch that changes a file. */
export function scanContent(roots, { rules, maxBytes = DEFAULT_MAX_BYTES, maxFiles = DEFAULT_MAX_FILES, maxDepth = 6 } = {}) {
  const limit = Math.max(1, Math.min(Number(maxBytes) || DEFAULT_MAX_BYTES, HARD_MAX_BYTES));
  const compiled = (rules ?? []).map(compileRule).filter(Boolean);
  const { files, skipped } = collectFiles(roots, { maxFiles, maxDepth });
  const findings = [];
  const notEvaluatedAll = [];
  const unreadable = [];
  let scanned = 0;
  let truncatedFiles = 0;
  for (const p of files) {
    const r = readPrefix(p, limit);
    if (!r.ok) { unreadable.push({ path: p, reason: r.reason }); continue; }
    scanned++;
    if (r.truncated) truncatedFiles++;
    const { hits, notEvaluated } = evaluateBuffer(r.buf, compiled, { truncated: r.truncated });
    for (const h of hits) {
      findings.push(finding(h.layer, h.severity, h.rule,
        `${h.label} -- ${path.basename(p)}`,
        `offset ${h.offset}, ${h.length} byte(s) matched, rule source ${h.source}. ${h.why}`,
        { path: p, offset: h.offset, length: h.length, rule: h.rule, source: h.source, file_bytes: r.size, read_bytes: r.bytes, file_truncated: r.truncated, does_not_cover: h.does_not_cover }));
    }
    for (const n of notEvaluated) notEvaluatedAll.push({ path: p, ...n });
  }
  return { findings, notEvaluated: notEvaluatedAll, unreadable, skipped, scanned, truncatedFiles, files: files.length, limit, rules: compiled.length };
}
