/**
 * AikawaMei - revocation list
 *
 * THE STEP AFTER "THIS FILE MATTERS": WHICH LOGINS IT MEANS.
 *
 * The sessions target answers "what did the automation leave behind" by reading NAMES, and its
 * boundary says so: the file is never opened, so an export that expired last year is reported as
 * loudly as a live one, and nothing here knows which sites it covers. That is the right boundary for
 * an audit and the wrong one for a cleanup. A file deleted from disk is not a session ended -- the
 * token on the other side keeps working until somebody revokes it, and the person doing the revoking
 * needs the list of places to go.
 *
 * This module produces that list. It opens a file ONLY when the format is one whose sites can be
 * read out of a fixed field, and it reads only that field:
 *
 *   netscape      a `cookies.txt` jar -- the domain column, which is the first column
 *   har           an HTTP archive -- `log.entries[].request.url`, and only the host of each
 *   storage_state Playwright's storage state -- the `origins[].origin` field, plus cookie domains
 *
 * Everything else is answered with the honest non-answer plus the way to find out: a Chrome profile
 * store, a Firefox logins database and an automation profile directory all hold credentials whose
 * sites are behind a key or a schema, and reading them would mean decrypting a credential store.
 * This module does not do that and says which file to open instead.
 *
 * WHAT IT DOES NOT DO: it revokes nothing, logs out of nothing, contacts nothing. There is no action
 * in it at all -- the output is a list and the sentence that says the tool cannot confirm the list
 * was carried out. An expiry date proves nothing about liveness (a session can be revoked early, or
 * a token refreshed), so "still valid" is not a claim this or any static reader can make.
 */
import fs from "node:fs";

export const REVOKE_SCHEMA = "aikawamei-revoke/1";

/** Per-file ceiling for the three readable formats. A larger file is reported, never half-parsed. */
export const REVOKE_MAX_BYTES = 4 * 1024 * 1024;

/** The formats whose sites are readable from a fixed field, and what that field is. */
export const REVOKE_FORMATS = {
  netscape: {
    label: "Netscape cookie jar",
    field: "the domain column (column 1 of each non-comment line)",
    carries: "live cookie values for every domain in the jar",
  },
  har: {
    label: "HTTP archive",
    field: "log.entries[].request.url, reduced to its host",
    carries: "request and response headers, including Authorization and Cookie",
  },
  storage_state: {
    label: "Playwright storage state",
    field: "origins[].origin, plus cookie domains",
    carries: "cookies, localStorage and any bearer token kept there",
  },
};

/**
 * Which of the readable formats a file name is, or null.
 *
 * By name, because that is all the caller has: this is reached from a sessions hit, and a sessions
 * hit is a name. The guess is then confirmed by the parse -- a file named `cookies.txt` that holds
 * JSON produces zero domains rather than a wrong answer, and lands in `unparsed`.
 */
export function classifySessionFile(name) {
  const n = String(name ?? "").toLowerCase();
  if (!n) return null;
  if (n.endsWith(".har")) return "har";
  // `storage-state` as well as `storage_state`: the harnesses write both, and a prefixed one
  // (`github-storage-state.json`) is the common shape. Measured: the first version required an
  // underscore or nothing, so a file named with a hyphen classified as nothing at all.
  if (/storage[-_]?state.*\.json$/.test(n)) return "storage_state";
  // A jar is often prefixed by the site it belongs to (`site-cookies.txt`), so the name has to match
  // at a separator rather than only at the start.
  if (/(^|[-_.])cookies?\.txt$/.test(n) || /(^|[-_.])cookie.*\.txt$/.test(n)) return "netscape";
  return null;
}

/** A hostname out of a URL, or null. Deliberately tiny: a URL that will not parse yields nothing. */
export function hostOf(value) {
  const s = String(value ?? "").trim();
  if (!s) return null;
  try {
    const u = new URL(s.includes("://") ? s : `https://${s}`);
    return u.hostname ? u.hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Netscape jar -> the domains it holds, in the order first seen. Comments and malformed rows skipped. */
export function parseNetscapeCookies(text) {
  const out = [];
  const seen = new Set();
  let rows = 0;
  let skipped = 0;
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // `#HttpOnly_` marks an http-only cookie and is NOT a comment; every other `#` line is.
    if (trimmed.startsWith("#") && !trimmed.startsWith("#HttpOnly_")) continue;
    rows += 1;
    const cols = trimmed.split("\t");
    if (cols.length < 7) { skipped += 1; continue; }
    const raw = cols[0].replace(/^#HttpOnly_/, "");
    const host = hostOf(raw.replace(/^\./, "")) ?? (raw.replace(/^\./, "").toLowerCase() || null);
    if (!host) { skipped += 1; continue; }
    // A leading dot means "this domain and its subdomains"; both are the same place to revoke.
    if (!seen.has(host)) { seen.add(host); out.push({ host, row: rows }); }
  }
  // A jar is one that YIELDED a domain. Counting non-comment rows was the first rule and it was too
  // wide: a file named cookies.txt holding `{ }` has one row and no domains, and reported itself as
  // a readable jar with an empty site list -- which reads as "nothing to revoke" rather than as
  // "this was not a jar".
  return { hosts: out, rows, skipped, looksLikeJar: out.length > 0 };
}

/** HAR -> hosts, from request URLs only. A malformed document yields zero, never a guess. */
export function parseHarHosts(text) {
  let doc;
  try { doc = JSON.parse(String(text ?? "")); } catch { return { hosts: [], entries: 0, skipped: 0, parsed: false }; }
  const entries = Array.isArray(doc?.log?.entries) ? doc.log.entries : null;
  if (!entries) return { hosts: [], entries: 0, skipped: 0, parsed: false };
  const seen = new Map();
  let skipped = 0;
  for (const e of entries) {
    const host = hostOf(e?.request?.url);
    if (!host) { skipped += 1; continue; }
    seen.set(host, (seen.get(host) ?? 0) + 1);
  }
  return {
    hosts: [...seen.entries()].map(([host, requests]) => ({ host, requests })),
    entries: entries.length, skipped, parsed: true,
  };
}

/** Playwright storage state -> origins, plus any cookie domains that are not already an origin. */
export function parseStorageStateOrigins(text) {
  let doc;
  try { doc = JSON.parse(String(text ?? "")); } catch { return { hosts: [], parsed: false }; }
  const hosts = [];
  const seen = new Set();
  const origins = Array.isArray(doc?.origins) ? doc.origins : [];
  for (const o of origins) {
    const host = hostOf(o?.origin);
    if (host && !seen.has(host)) { seen.add(host); hosts.push({ host, from: "origin" }); }
  }
  const cookies = Array.isArray(doc?.cookies) ? doc.cookies : [];
  for (const c of cookies) {
    const host = hostOf(String(c?.domain ?? "").replace(/^\./, ""));
    if (host && !seen.has(host)) { seen.add(host); hosts.push({ host, from: "cookie" }); }
  }
  return { hosts, parsed: Array.isArray(doc?.origins) || Array.isArray(doc?.cookies) };
}

/**
 * Read one file and reduce it to what the revoke list needs.
 *
 * `io.read` is injected so the suite can drive every branch without a file on disk, and so the size
 * ceiling is a value the test can reach instead of a number that has to be trusted.
 */
export function revokeOne(fullPath, format, io = { statOf: null, read }) {
  const reader = io.read ?? ((p, max) => fs.readFileSync(p, { encoding: "utf8", flag: "r" }).slice(0, max));
  const stat = io.statOf ? io.statOf(fullPath) : null;
  if (stat && typeof stat.size === "number" && stat.size > REVOKE_MAX_BYTES) {
    return {
      path: fullPath, format, readable: false,
      why: `larger than the ${REVOKE_MAX_BYTES} byte ceiling; a partial parse would name some sites and miss others, which reads as a complete list`,
      hosts: [],
    };
  }
  let text;
  try { text = reader(fullPath, REVOKE_MAX_BYTES); } catch (e) {
    // A bare errno is not a sentence. The list this lands in is read by a person deciding what to
    // revoke, and "ENOENT" beside a path tells them nothing about whether the file moved or they
    // mistyped the root.
    return { path: fullPath, format, readable: false, why: `could not be read: ${String((e && e.message) || e)}`, hosts: [] };
  }
  if (format === "netscape") {
    const r = parseNetscapeCookies(text);
    return {
      path: fullPath, format, readable: r.looksLikeJar, why: r.looksLikeJar ? null : "no tab-separated cookie rows found",
      hosts: r.hosts.map((h) => h.host), detail: { rows: r.rows, skipped: r.skipped },
    };
  }
  if (format === "har") {
    const r = parseHarHosts(text);
    return {
      path: fullPath, format, readable: r.parsed, why: r.parsed ? null : "not a HAR document (log.entries missing or unparseable)",
      hosts: r.hosts.map((h) => h.host), detail: { entries: r.entries, skipped: r.skipped },
    };
  }
  if (format === "storage_state") {
    const r = parseStorageStateOrigins(text);
    return {
      path: fullPath, format, readable: r.parsed, why: r.parsed ? null : "not a storage state (no origins or cookies array)",
      hosts: r.hosts.map((h) => h.host), detail: { from: r.hosts.map((h) => h.from) },
    };
  }
  return { path: fullPath, format, readable: false, why: "unknown format", hosts: [] };
}

/**
 * Turn sessions hits into a revoke list.
 *
 * `hits` is what `aikawamei_sessions` produced: `[{ root, path }]`, where `path` may be relative to
 * `root`. Everything else -- a directory hit, a profile store, an artifact -- is carried into
 * `notReadable` with the sentence that says why and the way to find out.
 */
export function revokePlan(hits = [], io = { statOf: null, read: undefined }) {
  const readable = [];
  const notReadable = [];
  const sites = new Map();

  for (const hit of Array.isArray(hits) ? hits : []) {
    const rel = typeof hit?.path === "string" ? hit.path : null;
    if (!rel) continue;
    const full = typeof hit.root === "string" && hit.root ? `${hit.root.replace(/[\\/]+$/, "")}/${rel.replace(/^[\\/]+/, "")}` : rel;
    const name = rel.split(/[\\/]/).pop() ?? rel;
    const format = classifySessionFile(name);
    if (!format) {
      notReadable.push({
        path: full,
        why: "this name is not one of the three formats whose sites can be read from a fixed field " +
             "(a cookie jar, a HAR, a storage state). The file still holds credentials -- the sites are behind a key, " +
             "a schema, or a name that says nothing about its contents.",
        how_to_find_out: name.toLowerCase().endsWith(".sqlite") || /^login data/i.test(name)
          ? "open it with the browser that owns it, or run sqlite3 and list the origin/url column; the key that decrypts it sits beside it"
          : "open the directory it sits in and look for the framework's report or the browser's own history for that profile",
      });
      continue;
    }
    const one = revokeOne(full, format, io);
    if (!one.readable) {
      notReadable.push({
        path: full, format,
        why: one.why,
        how_to_find_out: `open the file and read ${REVOKE_FORMATS[format].field}`,
      });
      continue;
    }
    readable.push({
      path: full, format, hosts: one.hosts,
      carries: REVOKE_FORMATS[format].carries,
      read_field: REVOKE_FORMATS[format].field,
      detail: one.detail ?? null,
    });
    for (const host of one.hosts) {
      const entry = sites.get(host) ?? { host, sources: [], carries: new Set() };
      if (!entry.sources.includes(full)) entry.sources.push(full);
      entry.carries.add(REVOKE_FORMATS[format].carries);
      sites.set(host, entry);
    }
  }

  const siteList = [...sites.values()]
    .sort((a, b) => a.host.localeCompare(b.host))
    .map((s) => ({
      host: s.host,
      sources: s.sources,
      what_it_can_do: [...s.carries],
      revoke: [
        `sign out of every device/session on ${s.host}`,
        `change the password on ${s.host} if the credential lived in one of these files`,
        `revoke any application token or API key issued for ${s.host} from its account settings`,
      ],
    }));

  return { readable, notReadable, sites: siteList };
}

/** What the report says about itself. Attached to every response, because the limits are the point. */
export const REVOKE_NOT_CLAIMED = [
  "That a listed session is still valid. A token can be revoked early or refreshed, so a static reader cannot tell a live session from an expired one -- only the site can answer that.",
  "That revoking in one place covers another. A cookie on api.example.com and a token in a HAR for example.com are two credentials, and both appear here as separate hosts.",
  "That carrying out this list makes the machine clean. It ends the sessions these files carried; it does not remove the files (aikawamei_clean), and it does not find the foothold (aikawamei_triage).",
  "That anything was revoked. This tool performs no network action and no account operation of any kind. The list is for a person.",
];
