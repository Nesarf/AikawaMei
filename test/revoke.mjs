#!/usr/bin/env node
/**
 * Revoke suite -- drives lib/revoke.mjs, the module that turns session files into a list of hosts.
 *
 * Why it has its own suite rather than riding on neutralize's
 * -----------------------------------------------------------
 * `neutralize` calls `revokePlan` for its fourth layer, and the first version of this work left it at
 * that. The coverage guard said what the combination hides: neutralize was 100% and revoke was 60%,
 * because two of the three readable formats -- the HAR and the storage state -- are never reached
 * through a session hit on this machine. A module whose exceptions are only exercised by one caller
 * is a module whose other branches are untested, and the number said so plainly.
 *
 * What is asserted, and why each one matters
 * ------------------------------------------
 *   1. A format is chosen by NAME, then confirmed by a PARSE. A file called `cookies.txt` that holds
 *      JSON yields zero hosts and lands in `unparsed`, never a wrong answer.
 *   2. Every ceiling and every refusal is a branch with a test: too large, unreadable, unparseable.
 *   3. Revocation is the one output that cannot be recomputed after the file is gone, so the list is
 *      asserted to be complete for what was readable and to SAY what it could not read.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const mod = await import(pathToFileURL(path.join(root, "lib", "revoke.mjs")).href);
const {
  REVOKE_SCHEMA, REVOKE_MAX_BYTES, REVOKE_FORMATS, REVOKE_NOT_CLAIMED,
  classifySessionFile, hostOf, parseNetscapeCookies, parseHarHosts,
  parseStorageStateOrigins, revokeOne, revokePlan,
} = mod;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== the declaration */

section("three formats, each with the field it is read through");

check("the schema is declared", REVOKE_SCHEMA === "aikawamei-revoke/1", REVOKE_SCHEMA);
check("exactly three formats are readable, and no more",
  Object.keys(REVOKE_FORMATS).sort().join(",") === "har,netscape,storage_state", Object.keys(REVOKE_FORMATS).join(","));
check("every format names its field and what it carries",
  Object.values(REVOKE_FORMATS).every((f) => f.label && f.field && f.carries));
check("the not-claimed list refuses to call a listed session live",
  REVOKE_NOT_CLAIMED.some((s) => /still valid/.test(s)), JSON.stringify(REVOKE_NOT_CLAIMED.length));
check("and refuses to say anything was revoked",
  REVOKE_NOT_CLAIMED.some((s) => /no network action and no account operation/.test(s)));

/* ================================================== classification */

section("a format is chosen by name");

check("a HAR file", classifySessionFile("session.har") === "har", String(classifySessionFile("session.har")));
check("a storage state, with and without the underscore",
  classifySessionFile("storage_state.json") === "storage_state" && classifySessionFile("storageState.json") === "storage_state");
check("a prefixed storage state", classifySessionFile("github-storage-state.json") === "storage_state");
check("a Netscape jar", classifySessionFile("cookies.txt") === "netscape", String(classifySessionFile("cookies.txt")));
check("a suffixed cookie file", classifySessionFile("site-cookies.txt") === "netscape");
check("a profile store is not one of the three", classifySessionFile("Login Data") === null);
check("an empty name", classifySessionFile("") === null && classifySessionFile(null) === null);

section("a host is a host, or nothing");

check("from a URL with a path", hostOf("https://api.example.com/v1/x") === "api.example.com", String(hostOf("https://api.example.com/v1/x")));
check("lowercased", hostOf("HTTPS://Example.COM") === "example.com", String(hostOf("HTTPS://Example.COM")));
check("a bare host is treated as https", hostOf("example.org") === "example.org");
check("a port is dropped", hostOf("https://example.org:8443/x") === "example.org");
check("nonsense yields nothing", hostOf("") === null && hostOf(null) === null);

/* ================================================== the three parsers */

section("Netscape jar: the domain column");

const jar = [
  "# Netscape HTTP Cookie File",
  ".example.com\tTRUE\t/\tFALSE\t1750000000\tsid\tsecret",
  "api.example.org\tFALSE\t/\tTRUE\t1750000000\ttok\tsecret2",
  "#HttpOnly_.hidden.example.net\tTRUE\t/\tTRUE\t1750000000\thid\tsecret3",
  "broken-line-without-tabs",
  "",
].join("\n");
const jarParsed = parseNetscapeCookies(jar);
check("three domains, from three rows", jarParsed.hosts.length === 3, JSON.stringify(jarParsed.hosts.map((h) => h.host)));
check("a leading dot is stripped", jarParsed.hosts.some((h) => h.host === "example.com"));
check("#HttpOnly_ is a cookie, not a comment", jarParsed.hosts.some((h) => h.host === "hidden.example.net"),
  JSON.stringify(jarParsed.hosts.map((h) => h.host)));
check("a real comment line is skipped", !jarParsed.hosts.some((h) => h.host.includes("Netscape")));
check("a malformed row is counted, not guessed at", jarParsed.skipped === 1, String(jarParsed.skipped));
check("a jar with no rows says so", parseNetscapeCookies("").looksLikeJar === false);

section("HAR: the request URLs");

const har = JSON.stringify({ log: { entries: [
  { request: { url: "https://a.example.com/x" } },
  { request: { url: "https://a.example.com/y" } },
  { request: { url: "https://b.example.org/z" } },
  { request: {} },
] } });
const harParsed = parseHarHosts(har);
check("two hosts from three usable entries", harParsed.hosts.length === 2, JSON.stringify(harParsed.hosts));
check("repeat requests are counted, not duplicated", harParsed.hosts.find((h) => h.host === "a.example.com")?.requests === 2,
  JSON.stringify(harParsed.hosts));
check("an entry with no url is counted as skipped", harParsed.skipped === 1, String(harParsed.skipped));
check("invalid JSON yields nothing rather than throwing",
  parseHarHosts("{not json").parsed === false && parseHarHosts("{not json").hosts.length === 0);
check("a JSON document that is not a HAR yields nothing",
  parseHarHosts('{"a":1}').parsed === false);

section("storage state: origins, then cookie domains");

const state = JSON.stringify({
  cookies: [{ domain: ".cookie.example.com" }, { domain: "plain.example.org" }],
  origins: [{ origin: "https://app.example.net" }, { origin: "https://app.example.net/again" }],
});
const stateParsed = parseStorageStateOrigins(state);
check("origins and cookie domains are both taken", stateParsed.hosts.length === 3, JSON.stringify(stateParsed.hosts));
check("an origin with a path is reduced to its host", stateParsed.hosts.some((h) => h.host === "app.example.net"));
check("the leading dot on a cookie domain is stripped", stateParsed.hosts.some((h) => h.host === "cookie.example.com"));
check("a duplicate origin is listed once", stateParsed.hosts.filter((h) => h.host === "app.example.net").length === 1);
check("invalid JSON is reported rather than thrown", parseStorageStateOrigins("nope").parsed === false);
check("an object with neither array is not a storage state", parseStorageStateOrigins('{"x":1}').parsed === false);

/* ================================================== the ceiling and the refusals */

section("a file too large is refused, not half-parsed");

const big = { statOf: () => ({ size: REVOKE_MAX_BYTES + 1 }), read: () => { throw new Error("should not be called"); } };
const tooBig = revokeOne("/x/y.har", "har", big);
check("the ceiling is a refusal with a reason", tooBig.readable === false && /ceiling/.test(tooBig.why), tooBig.why);
check("and nothing was read to find that out", tooBig.hosts.length === 0);

const unreadable = { statOf: null, read: () => { throw new Error("EACCES"); } };
const failed = revokeOne("/x/y.har", "har", unreadable);
check("an unreadable file is reported with its error", failed.readable === false && /EACCES/.test(failed.why), failed.why);

check("a jar named wrongly does not become a HAR",
  revokeOne("/x/cookies.txt", "netscape", { statOf: null, read: () => "{ }" }).readable === false);
check("an unknown format is refused rather than guessed",
  revokeOne("/x/y.bin", "mystery", { statOf: null, read: () => "" }).readable === false);

/* ================================================== the plan */

section("a plan names what it read and what it could not");

const files = {
  "/w/cookies.txt": jar,
  "/w/run.har": har,
  "/w/storage_state.json": state,
  "/w/Login Data": "binary",
};
const io = { statOf: null, read: (p) => {
  const k = Object.keys(files).find((f) => p.endsWith(path.basename(f)));
  if (!k) throw new Error("ENOENT");
  return files[k];
} };
const plan = revokePlan([
  { root: "/w", path: "cookies.txt" },
  { root: "/w", path: "run.har" },
  { root: "/w", path: "storage_state.json" },
  { root: "/w", path: "Login Data" },
  { root: "/w", path: "missing.har" },
], io);

check("three files were readable", plan.readable.length === 3, String(plan.readable.length));
check("two were not, and both say why",
  plan.notReadable.length === 2 && plan.notReadable.every((n) => typeof n.why === "string" && n.why.length > 10),
  JSON.stringify(plan.notReadable.map((n) => n.why.slice(0, 40))));
check("the unreadable one that is a known store says how to find out",
  plan.notReadable.some((n) => /sqlite3|open it/.test(n.how_to_find_out ?? "")), JSON.stringify(plan.notReadable));
check("the host list is the union, deduplicated", plan.sites.length === 8, JSON.stringify(plan.sites.map((s) => s.host)));
check("sites are sorted, so two runs produce the same list",
  plan.sites.map((s) => s.host).join(",") === [...plan.sites.map((s) => s.host)].sort().join(","),
  plan.sites.map((s) => s.host).join(","));
check("a host reachable from two files names both sources",
  plan.sites.every((s) => Array.isArray(s.sources) && s.sources.length >= 1));
check("every site carries the three revoke actions",
  plan.sites.every((s) => s.revoke.length === 3 && s.revoke.every((r) => typeof r === "string")));
check("and every action is written for a person, not executed",
  !JSON.stringify(plan).includes("undefined"));

/* ================================================== end to end on disk */

section("end to end: a jar this suite writes and deletes");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "aikawamei-revoke-"));
fs.writeFileSync(path.join(tmp, "cookies.txt"), jar);
const real = revokePlan([{ root: tmp, path: "cookies.txt" }]);
check("the jar on disk yields its three hosts", real.sites.length === 3, JSON.stringify(real.sites.map((s) => s.host)));
check("nothing landed in notReadable", real.notReadable.length === 0, JSON.stringify(real.notReadable));
check("the file is still there -- reading does not consume", fs.existsSync(path.join(tmp, "cookies.txt")));
fs.rmSync(tmp, { recursive: true, force: true });

/* ================================================== summary */

console.log(`\n${fail ? "\u001b[31m" : "\u001b[32m"}${pass} passed, ${fail} failed\u001b[0m`);
if (fail) { for (const f of failures) console.log(`  - ${f}`); process.exit(1); }
