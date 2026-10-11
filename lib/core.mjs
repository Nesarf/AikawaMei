/**
 * AikawaMei - core
 *
 * Pure Node beyond the MCP SDK. The CLI and the MCP stdio server share this
 * single TOOLS[].execute -- there is deliberately no second implementation.
 *
 * ===================================================================
 * DESIGN DISCIPLINE (inherited from the original threat-model analysis; do not soften)
 * ===================================================================
 *
 * 1. This tool performs a STATIC audit only: it reads files, never starts Tor, and
 *    never touches the network. The single outbound call is the version lookup,
 *    which only queries Tor Project's public release metadata.
 *
 * 2. This tool cannot address traffic correlation, endpoint compromise, or anything
 *    that happens after decryption. Every response MUST carry boundary_notice --
 *    that is not decoration.
 *
 * 3. Separating the layers is the whole reason this tool exists:
 *      content layer  -- encryption; answers "can they read it"
 *      metadata layer -- the focus of this audit; answers "can they link it"
 *      endpoint layer -- cryptography cannot reach here; only isolation and hygiene can
 *      social layer   -- people, always the largest variable
 *    Payload encryption helps the metadata layer by roughly zero. Any output that
 *    conflates the two is wrong.
 *
 * 4. An auditor can only report STATIC RESIDUE AND CONFIGURATION POSTURE.
 *    It must never say "you are safe now".
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { httpsGetJson, detectProxy } from "./net.mjs";
import {
  exists, statOf, readText, readJson, listDir,
  fmtBytes, fmtTime, finding, parseTorrc, parsePrefs, probeInputsFor,
} from "./shared.mjs";
import { discoverFirefoxProfiles, auditFirefoxProfile, findFirefoxApplication, pickDefaultProfile } from "./firefox.mjs";
import { inspectEmblem, readShippedEmblem } from "./emblem.mjs";
import {
  CATALOG_VERSION, CHECKS_SCHEMA, CHECK_CATALOG, catalogDigest, checkById, checksFor,
  evaluateBuiltins, factsFrom, validateFindings, OPERATIONS, OPERATION_ORDER, networkClause,
} from "./checks.mjs";
import { BASELINE_SCHEMA, baselineFrom, diffBaselines, unwrapBaseline, validateBaseline } from "./baseline.mjs";
import { HANDOFF_SCHEMA, handoffFindings } from "./handoff.mjs";
import {
  SESSIONS_SCHEMA, SESSIONS_NOT_DETERMINED,
  defaultSessionRoots, planSessionRoots, scanSessionRoot,
} from "./sessions.mjs";
import { VAULT_SCHEMA, appendRecord, sealValue, verifyFile } from "./vault.mjs";
import {
  SCOPE_NOTICE, classifyTargets, declaredScope, defaultScope, scopeReport,
} from "./scope.mjs";
import {
  COLLECT_SCHEMA, COLLECT_NOT_REACHABLE, collectInto, destinationInsideSources,
} from "./collect.mjs";
import {
  SELFCHECK_SCHEMA, SELF_NOT_POSSIBLE,
  compareManifests, manifestOf, readManifest, selfBoundary,
} from "./selfcheck.mjs";
import {
  TRIAGE_SCHEMA, TRIAGE_NOT_READABLE,
  clustersOf, findingsFor, readPrefetch, readScheduledTasks, readStartupFolders,
  readUserWritableExecutables, readWerReports, realTriageIo, timelineOf,
} from "./triage.mjs";

// Re-exported so callers and tests can keep importing the parsers from the core.
export { parseTorrc, parsePrefs };
// The operation vocabulary is declared with the catalog and read by the tools; re-exported for the
// same reason, and so that a test can assert a tool's declaration against the closed set without
// reaching past the core for it.
export { OPERATIONS, OPERATION_ORDER, networkClause };

export const VERSION = "0.2.0";

/**
 * Response schemas.
 *
 * Every tool response names the schema it conforms to. A caller -- a harness, a script, a
 * person comparing two runs -- then has something stable to key on, instead of inferring
 * "the shape probably has not changed" from the absence of a version number. Schemas change
 * only when the shape changes; prose and new fields are additive within a schema.
 */
export const ENV_SCHEMA = "aikawamei-env/1";
export const AUDIT_SCHEMA = "aikawamei-audit/1";
export const VERSION_SCHEMA = "aikawamei-version/1";
export const ASSESS_SCHEMA = "aikawamei-assess/1";
export const BASELINE_REPORT_SCHEMA = "aikawamei-baseline-report/1";
export const FACTS_SCHEMA = "aikawamei-facts/1";
export { BASELINE_SCHEMA, CHECKS_SCHEMA };

/**
 * Safe serialization: tolerates BigInt and genuine circular references.
 * All output goes through this.
 *
 * "Circular" means an object that contains ITSELF, not an object that is merely reachable
 * twice. A shared reference is valid JSON and must be serialized in full both times -- the
 * audit response is exactly that shape, since a fact and a finding are two views of the same
 * evidence object. Tracking every object ever visited (rather than the ancestors of the
 * current path) replaced the second view with "[circular]" and silently dropped real data.
 */
export function safeStringify(value, indent = 0) {
  const ancestors = new Set();
  const walk = (v) => {
    if (typeof v === "bigint") return v.toString();
    if (v === undefined) return undefined;
    if (v === null || typeof v !== "object") return v;
    if (ancestors.has(v)) return "[circular]";
    // Honour toJSON the way JSON.stringify does, so a Date does not turn into an empty object.
    // A toJSON that returns its own receiver would recurse forever, hence the identity check.
    if (typeof v.toJSON === "function") {
      const j = v.toJSON();
      return j === v ? "[circular]" : walk(j);
    }
    ancestors.add(v);
    let out;
    if (Array.isArray(v)) {
      // JSON has no undefined, so an array slot becomes null exactly as it does natively.
      out = v.map((x) => {
        const r = walk(x);
        return r === undefined ? null : r;
      });
    } else {
      out = {};
      for (const k of Object.keys(v)) {
        const r = walk(v[k]);
        if (r !== undefined) out[k] = r;
      }
    }
    ancestors.delete(v);
    return out;
  };
  return JSON.stringify(walk(value), null, indent);
}

/* ------------------------------------------------ constants */

export const LAYERS = {
  build: { key: "build", label: "Build", question: "Are you running a version with known holes?" },
  transport: { key: "transport", label: "Transport", question: "What does the traffic look like on the wire - can it be fingerprinted or blocked?" },
  crypto: { key: "crypto", label: "Content / authorization", question: "Who can read the content, and who can even reach the destination?" },
  metadata: { key: "metadata", label: "Metadata", question: "Who talks to whom, when, and how often - content encryption cannot see this layer" },
  endpoint: { key: "endpoint", label: "Endpoint", question: "What has this machine left behind, and what happens if it is taken?" },
  social: { key: "social", label: "Social", question: "People." },
};

export const SEVERITY_ORDER = { ok: 0, info: 1, warn: 2, critical: 3 };

/** Known pluggable transports and how well they blend in. */
export const PT_KNOWLEDGE = {
  obfs4: { blend: "medium", note: "Randomized traffic that looks unlike common protocols; published traffic-analysis research targets it" },
  webtunnel: { blend: "high", note: "Mimics an ordinary HTTPS website; the mainstay of censorship circumvention since 2024" },
  meek_lite: { blend: "high", note: "Domain fronting; depends on CDN cooperation, and availability has declined in recent years" },
  conjure: { blend: "high", note: "Refraction networking - borrows unused address space from ISPs" },
  snowflake: { blend: "high", note: "Connects over WebRTC to real volunteer browsers; the exit is a volunteer, not a relay" },
  scramblesuit: { blend: "low", note: "Obsolete; do not rely on it alone" },
  obfs2: { blend: "low", note: "Deprecated" },
  obfs3: { blend: "low", note: "Deprecated" },
};

/**
 * The three lines that do not depend on what a tool does: what is out of scope, what is in scope,
 * and the misuse warning. The FIRST line does depend on it, and is derived by `boundaryFor`.
 */
const BOUNDARY_REST = [
  "It does NOT address: traffic correlation and timing analysis, endpoint compromise (malware / device seizure), or anything that happens after decryption.",
  // Was "It protects [configuration posture and static residue]" -- a bracket placeholder that was never
  // filled in, around a scope that stopped being true once the toolset grew past static residue: session
  // hygiene, foothold artefacts, a record chain and the installation's own manifest are none of them
  // "static residue". This line is on every response of every tool, so a line that is too narrow is too
  // narrow everywhere at once.
  "It protects what is visible without running anything: configuration posture, the residue software and sessions leave behind, and the artefacts that record a foothold. It is NOT an anti-tracking tool.",
  "A clean audit is NOT proof of safety. Treating it as one is a misuse.",
];

/**
 * The boundary notice for a tool that declares these operations.
 *
 * Derived rather than written, because the hand-written version was a single sentence carrying an
 * exception -- "never touches the network (except the version lookup)" -- and that sentence is
 * correct for the one tool that performs a lookup and too permissive for the seven that do not: it
 * leaves a reader unable to tell a tool that might reach out from one that cannot.
 *
 * The first line comes from the STRONGEST class declared, never the weakest, so a notice can only
 * ever be accurate about the tool it is attached to. A tool that grows a network operation without
 * declaring one now fails the suite instead of quietly shipping a false sentence, which is the same
 * shape as every other declared-and-enforced rule in this project.
 */
export function boundaryFor(operations = ["static"]) {
  const declared = new Set((Array.isArray(operations) ? operations : []).filter((o) => Object.prototype.hasOwnProperty.call(OPERATIONS, o)));
  if (!declared.size) declared.add("static");
  const parts = OPERATION_ORDER.filter((k) => declared.has(k)).map((k) => OPERATIONS[k].clause);
  const net = networkClause([...declared]);
  if (net) parts.push(net);
  const body = parts.length > 1 ? `${parts.slice(0, -1).join(", ")}, ${parts[parts.length - 1]}` : parts[0];
  return [`This tool ${body}.`, ...BOUNDARY_REST];
}

/** The widest notice any tool carries today. Each tool derives its own from what it declares. */
export const BOUNDARY_NOTICE = boundaryFor(["static", "lookup"]);

const OPS_STATIC = ["static"];
const OPS_WRITES = ["static", "writes"];
const OPS_LOOKUP = ["static", "lookup"];
const NOTICE_STATIC = boundaryFor(OPS_STATIC);
const NOTICE_WRITES = boundaryFor(OPS_WRITES);
const NOTICE_LOOKUP = boundaryFor(OPS_LOOKUP);

/* ------------------------------------------------ install discovery */

// The drive-letter sweep is DELIBERATELY bounded: A/B are legacy floppies, and probing
// further letters can block for a long time when a disconnected network drive is mapped.
// Pass an explicit `install` to audit anywhere else.
const DRIVE_LETTERS = "CDEFGHIJ".split("");

function candidateRoots() {
  const out = [];
  const home = os.homedir();
  for (const d of DRIVE_LETTERS) {
    out.push(`${d}:\\Tor Browser`);
    out.push(`${d}:\\tor browser`);
  }
  out.push(path.join(home, "Desktop", "Tor Browser"));
  out.push(path.join(home, "Documents", "Tor Browser"));
  out.push("C:\\Program Files\\Tor Browser");
  out.push("C:\\Program Files (x86)\\Tor Browser");
  return out;
}

/** Is this directory a Tor Browser install root (contains Browser/tbb_version.json)? */
function isInstallRoot(p) {
  return exists(path.join(p, "Browser", "tbb_version.json")) ||
         exists(path.join(p, "Browser", "firefox.exe"));
}

/** Shallow one-level sweep of a drive root looking for Tor directories. */
function shallowScanRoot(driveRoot) {
  const found = [];
  for (const e of listDir(driveRoot)) {
    if (!e.isDirectory()) continue;
    if (!/tor/i.test(e.name)) continue;
    const p = path.join(driveRoot, e.name);
    if (isInstallRoot(p)) found.push(p);
    else {
      // one level deeper
      for (const e2 of listDir(p)) {
        if (!e2.isDirectory()) continue;
        const p2 = path.join(p, e2.name);
        if (isInstallRoot(p2)) found.push(p2);
      }
    }
  }
  return found;
}

/**
 * Normalize a path into a de-duplication key.
 * Windows filesystems are case-insensitive -- without this, C:\Tor Browser and
 * C:\tor browser are counted as two separate installs (hit in practice).
 */
function canonKey(p) {
  let r;
  try { r = fs.realpathSync.native(p); }
  catch { try { r = fs.realpathSync(p); } catch { r = path.resolve(p); } }
  return process.platform === "win32" ? r.toLowerCase() : r;
}

/**
 * Discover every Tor Browser install on this machine.
 *
 * When `explicit` is given, only that path is considered (no full-drive sweep).
 * Otherwise candidate paths plus a shallow drive sweep are used.
 * @param {string=} explicit install root
 * @returns {Array<object>} results of describeInstall
 */
export function discoverInstalls(explicit) {
  const hits = new Map();
  const add = (p, how) => {
    // Ignore anything that is not a string: path.join throws on number/object, and tool
    // arguments come from untrusted callers (the matrix traverser crashed it with 12345 and {}).
    if (typeof p !== "string" || !p.trim()) return;
    if (!isInstallRoot(p)) return;
    let real;
    try { real = fs.realpathSync.native(p); } catch { real = path.resolve(p); }
    const key = canonKey(p);
    if (!hits.has(key)) hits.set(key, { root: real, found_by: how });
  };

  // Explicit means explicit: the caller said "audit this one", so do not go sweeping whole
  // drives (slow, and it mixes unrelated installs into the result - hit in practice).
  if (typeof explicit === "string" && explicit.trim()) {
    add(explicit, "explicit");
    return [...hits.values()].map((h) => describeInstall(h.root, h.found_by));
  }

  for (const c of candidateRoots()) {
    if (exists(c)) add(c, "candidate");
  }
  for (const d of DRIVE_LETTERS) {
    const dr = `${d}:\\`;
    if (!exists(dr)) continue;
    for (const p of shallowScanRoot(dr)) add(p, "scan");
  }

  return [...hits.values()].map((h) => describeInstall(h.root, h.found_by));
}

/** Read the structured facts about one install. */
export function describeInstall(root) {
  const browserDir = path.join(root, "Browser");
  const tbb = readJson(path.join(browserDir, "tbb_version.json"));
  const dataDir = path.join(browserDir, "TorBrowser", "Data");
  const torDataDir = path.join(dataDir, "Tor");
  const profileDir = path.join(dataDir, "Browser", "profile.default");

  const appIni = readText(path.join(browserDir, "application.ini")) || "";
  const fxVersion = (appIni.match(/^Version=(.+)$/m) || [])[1]?.trim() || null;

  return {
    root,
    browser_dir: browserDir,
    data_dir: torDataDir,
    profile_dir: profileDir,
    tor_browser_version: tbb?.version ?? null,
    channel: tbb?.channel ?? null,
    architecture: tbb?.architecture ?? null,
    firefox_version: fxVersion,
    drive: path.parse(root).root.replace(/\\$/, ""),
  };
}

/* ------------------------------------------------ per-layer checks */

function auditBuild(inst, stateText) {
  const out = [];
  const tb = inst.tor_browser_version;
  out.push(finding("build", tb ? "ok" : "warn", "tb-version",
    tb ? `Tor Browser version ${tb}` : "Could not determine the Tor Browser version",
    tb ? `channel ${inst.channel ?? "?"} / arch ${inst.architecture ?? "?"} / Firefox base ${inst.firefox_version ?? "?"}`
       : "Neither Browser/tbb_version.json nor application.ini was found; the install may be incomplete or modified.",
    { tor_browser_version: tb, channel: inst.channel, firefox: inst.firefox_version }));

  const torVer = (stateText?.match(/^TorVersion\s+(.+)$/m) || [])[1]?.trim();
  if (torVer) {
    out.push(finding("build", "info", "tor-version", `Inner Tor version: ${torVer}`,
      "The version of tor.exe. Tor Browser releases usually advance the Firefox base and Tor itself together; either one lagging is worth noticing.",
      { aikawamei_version: torVer }));
  }
  return out;
}

function auditTransport(entries, prefs, pctx) {
  const out = [];
  const bridges = entries.Bridge ?? [];
  const useBridges = (entries.UseBridges ?? []).some((v) => v.trim() === "1");
  const pts = entries.ClientTransportPlugin ?? [];

  // bridge overview
  const kinds = {};
  for (const b of bridges) {
    const k = (b.match(/^(\S+)/) || [, "?"])[1].toLowerCase();
    kinds[k] = (kinds[k] ?? 0) + 1;
  }
  const kindList = Object.entries(kinds).map(([k, n]) => `${k}x${n}`).join(", ");

  if (useBridges && bridges.length > 0) {
    const worst = Math.min(...Object.keys(kinds).map((k) => ({ high: 2, medium: 1, low: 0 }[PT_KNOWLEDGE[k]?.blend] ?? 1)));
    out.push(finding("transport", worst >= 1 ? "ok" : "warn", "bridges",
      `Bridges enabled (${kindList})`,
      "Bridges take the fact that you use Tor out of the public relay list - the first step of circumvention. " +
      (worst >= 1 ? "The chosen types have decent cover." : "But the chosen type offers poor cover; consider adding webtunnel/snowflake."),
      { bridges: kinds, count: bridges.length }));
  } else if (useBridges) {
    out.push(finding("transport", "warn", "bridges", "UseBridges is on but there are no Bridge lines",
      "The configuration is self-inconsistent; Tor may fail to start or fall back to a direct connection.", { use_bridges: true, bridge_count: 0 }));
  } else {
    out.push(finding("transport", "info", "bridges", "Bridges not enabled (connecting directly to public relays)",
      "This is normal on an unblocked network and gives the largest anonymity set. Bridges are required in a censored environment.",
      { use_bridges: false }));
  }

  // bridge-blend is a built-in check: it reads two prefs and reports one of them, which a
  // config-value variant expresses without any control flow.

  // uTLS fingerprint impersonation
  const utls = bridges.filter((b) => /utls-imitate=/.test(b)).map((b) => (b.match(/utls-imitate=(\S+)/) || [])[1]);
  if (utls.length) {
    out.push(finding("transport", "ok", "utls",
      `uTLS fingerprint impersonation detected (${[...new Set(utls)].join(", ")})`,
      "Makes the TLS ClientHello look like a common browser, defeating handshake-fingerprint identification. A genuine anti-fingerprinting measure.",
      { utls_imitate: [...new Set(utls)] }));
  }

  // domain fronting
  const fronts = bridges.filter((b) => /fronts=/.test(b)).map((b) => (b.match(/fronts=(\S+)/) || [])[1]);
  if (fronts.length) {
    out.push(finding("transport", "ok", "fronting",
      "Domain fronting detected (fronts=)",
      "Disguises the SNI as a high-reputation domain, defeating SNI-based blocking.",
      { fronts: [...new Set(fronts)].slice(0, 4) }));
  }

  // available pluggable transports
  if (pts.length) {
    const names = new Set();
    for (const p of pts) {
      const first = p.split(/\s+/)[0] ?? "";
      for (const nm of first.split(",")) if (nm) names.add(nm);
    }
    out.push(finding("transport", "info", "pt-list",
      `Pluggable transports loaded: ${[...names].join(", ")}`,
      "Available is not the same as in use; the entry above shows which bridge types are actually enabled.",
      { plugins: [...names], raw: pts }));
  }

  // deprecated transports
  const deprecated = Object.keys(kinds).filter((k) => PT_KNOWLEDGE[k]?.blend === "low");
  // Sum ALL deprecated kinds rather than looking only at the first one: otherwise a mix
  // such as obfs2x2 + obfs3x1 is missed (3 != 2).
  const deprecatedCount = deprecated.reduce((sum, k) => sum + kinds[k], 0);
  if (deprecatedCount > 0 && deprecatedCount === bridges.length) {
    out.push(finding("transport", "warn", "deprecated-pt",
      `The only transports in use are deprecated: ${deprecated.join(", ")}`,
      "obfs2/obfs3/scramblesuit are no longer considered effective protection and are easy to identify.",
      { deprecated }));
  }

  // bridge-blend and quickstart are built-in checks, evaluated here with this layer's others.
  // The first version of this migration had no transport-layer evaluation at all, so both simply
  // stopped running -- a check that is catalogued but never reached is worse than one that is
  // missing, because the catalog still claims it.
  out.push(...evaluateBuiltins("tor", pctx, { layer: "transport" }));

  return out;
}

function auditCrypto(entries, inst, pctx) {
  const out = [];
  const authDir = (entries.ClientOnionAuthDir ?? [])[0];

  if (authDir) {
    // onion-auth-empty and onion-auth-keys are built-in checks now; this finding reports the
    // configuration itself plus how many keys the directory currently holds, which no probe
    // shape expresses (it is a configured value and a count in one finding).
    const keys = listDir(authDir).filter((e) => e.isFile() && /\.auth_private$/i.test(e.name));
    out.push(finding("crypto", "ok", "onion-auth-configured",
      "Onion service client authorization directory configured",
      "A v3 onion address is itself a public key (you cannot connect without knowing it); client authorization adds another layer - " +
      "only a key holder can make that service respond. This is genuine conditional reachability, with no change to the Tor protocol.",
      { dir: authDir, key_files: keys.length }));
  }
  // onion-auth-absent, hs-keys and the rest of this layer are built-in checks.
  out.push(...evaluateBuiltins("tor", pctx, { layer: "crypto" }));

  return out;
}

/**
 * Metadata layer - the reason this tool exists.
 * Content encryption cannot see this layer at all, and this is where things actually go wrong.
 */
function auditMetadata(inst, pctx) {
  const out = [];
  const dd = inst.data_dir;

  // state: guard selection and usage residue
  const statePath = path.join(dd, "state");
  const st = statOf(statePath);
  const stateText = readText(statePath);
  if (st) {
    const lastWritten = (stateText?.match(/^LastWritten\s+(.+)$/m) || [])[1]?.trim() ?? null;
    // Modern Tor (0.4.x) writes  Guard in=default rsa_id=... nickname=...
    // Legacy writes EntryGuard ... . Both must be recognized - matching only the legacy
    // form produces a false "no guards" report (hit in practice).
    const guardLines = (stateText?.match(/^Guard\s+in=\S+/gm) ?? []).length
                     + (stateText?.match(/^EntryGuard[^\s]*/gm) ?? []).length;
    const guardSets = [...new Set((stateText?.match(/^Guard\s+in=\S+/gm) ?? [])
      .map((s) => s.replace(/^Guard\s+in=/, "")))];
    const bridgeLines = (stateText?.match(/^Bridge[^\s]*/gm) ?? []).length;
    const circBins = (stateText?.match(/^CircuitBuildTimeBin/gm) ?? []).length;

    out.push(finding("metadata", "warn", "state-file",
      `state file retained (${fmtBytes(st.size)}, last written ${fmtWritten(lastWritten)})`,
      "state records guard selection, bridge usage and circuit build-time distribution - the single most sensitive file in a Tor client. " +
      "Content encryption does nothing for it. If the device is seized, it can reconstruct the outline of your connection history.",
      { size: st.size, last_written: lastWritten, mtime: st.mtime.toISOString(), guards: guardLines, state_bridge_lines: bridgeLines, circuit_bins: circBins }));

    if (guardLines === 0) {
      out.push(finding("metadata", circBins > 0 ? "warn" : "info", "state-no-guards",
        "No guard records found in state",
        circBins > 0
          ? "Circuit build times exist but no guard entries. This tool makes no assertion - confirm by hand: did circuits ever build successfully? Was state reset or cleared?"
          : "This install may never have built a circuit successfully.",
        { guards: 0, circuit_bins: circBins }));
    } else {
      out.push(finding("metadata", "warn", "state-guards",
        `state records ${guardLines} guard(s)${guardSets.length ? ` (sets: ${guardSets.join(", ")})` : ""}`,
        "Guards are the metadata most directly tied to who you are - they bind you to an entry observation point. Content encryption does nothing here. " +
        "The guard set accumulates over time: the more it accumulates, the larger the surface that can be correlated retroactively.",
        { guards: guardLines, sets: guardSets }));
    }
  }

  // profile-times, the descriptor caches, pt_state, session checkpoints and places are built-in
  // checks now: their names, titles, severities and boundaries live in the catalog, and their
  // probes read the same files this function used to. They run here, with this layer's other
  // checks, so that calling the Tor audit directly yields the same set the tool returns.
  out.push(...evaluateBuiltins("tor", pctx, { layer: "metadata" }));

  return out;
}

function fmtWritten(s) {
  return s ? s : "unknown";
}

function auditEndpoint(inst, pctx) {
  const out = [];

  const drive = inst.drive;
  const systemDrive = (process.env.SystemDrive ?? "C:").replace(/\\$/, "");
  if (drive && drive.toUpperCase() !== systemDrive.toUpperCase()) {
    out.push(finding("endpoint", "ok", "disk-location",
      `Installed on drive ${drive} (not the system drive)`,
      "Separated from the system drive: easier to handle as a whole, and no Tor data lands in the system temp directory.",
      { drive, system_drive: systemDrive }));
  } else {
    out.push(finding("endpoint", "info", "disk-location",
      `Installed on the system drive ${drive}`,
      "Not an error, but keeping Tor on the same volume as the system means formatting or forensics will handle them together.",
      { drive, system_drive: systemDrive }));
  }

  // The stray-trace pair and the persistence statement are built-in checks now: the six candidate
  // paths are catalog data rather than a loop, and the probe applies the same case-insensitive
  // compare that stopped the install's own directory being reported as a copy of itself.
  out.push(...evaluateBuiltins("tor", pctx, { layer: "endpoint" }));

  return out;
}

/* ------------------------------------------------ environment probe */

export function detectEnvironment() {
  const env = {
    mode: "cli",
    platform: process.platform,
    arch: process.arch,
    node: process.version,
    homedir: os.homedir(),
    system_drive: process.env.SystemDrive ?? null,
    temp: os.tmpdir(),
  };
  // Which entry point is running: the MCP stdio server, or the CLI. Only the entry script's
  // directory is inspected, never the whole argv (which includes the absolute cwd) -
  // otherwise a project living under any directory containing "mcp" would make the CLI
  // report itself as mcp.
  const entry = (process.argv[1] ?? "").replace(/\\/g, "/").toLowerCase();
  if (/\/mcp\//.test(entry)) env.mode = "mcp";
  return env;
}

/* ------------------------------------------------ version freshness */

export const TOR_VERSION_ENDPOINTS = {
  release: "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json",
  alpha: "https://aus1.torproject.org/torbrowser/update_3/alpha/downloads.json",
};

/** Mozilla publishes the current Firefox versions as one small JSON document. */
export const FIREFOX_VERSION_ENDPOINT = "https://product-details.mozilla.org/1.0/firefox_versions.json";
export const FIREFOX_CHANNEL_KEYS = {
  release: "LATEST_FIREFOX_VERSION",
  esr: "FIREFOX_ESR",
  beta: "LATEST_FIREFOX_RELEASED_DEVEL_VERSION",
  nightly: "FIREFOX_NIGHTLY",
};

export function cmpVer(a, b) {
  const pa = String(a).split(".").map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}

/* ------------------------------------------------ layer-mismatch assessment (the framework) */

/**
 * Four-layer model. Any assessment must state clearly that a problem in one layer
 * cannot be solved by a control from another.
 */
export const LAYER_MODEL = [
  {
    layer: "content", label: "Content",
    question: "Can anyone read the content itself?",
    answers_with: "End-to-end encryption (age / PGP / Signal Double Ratchet / AES-GCM)",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "The layer that is already solved best. Ordinary tooling suffices; it is not the bottleneck.",
  },
  {
    layer: "metadata", label: "Metadata",
    question: "Can anyone tell who talks to whom, when, and how often?",
    answers_with: "Mixnet (Loopix/Nym), metadata-hiding messengers (SimpleX/Cwtch), asynchronous mailboxes, onion services, cover traffic",
    solved_by_this_tool: false,          // this tool does NOT solve the metadata layer: it only audits static residue
    tool_role: "audits_static_residue",
    note: "Content encryption helps this layer by roughly zero. This is where most approaches go wrong.",
  },
  {
    layer: "endpoint", label: "Endpoint",
    question: "What has this machine left behind, and what happens if it is taken?",
    answers_with: "Environment isolation (Qubes/Whonix/Tails), full-disk encryption, minimal persistent state",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "Cryptography cannot reach this layer. An auditor can tell you what residue exists; it cannot remove it for you.",
  },
  {
    layer: "social", label: "Social",
    question: "What will people say, keep, or be asked?",
    answers_with: "No technical solution",
    solved_by_this_tool: false,
    tool_role: "none",
    note: "The most common point of failure in public cases. All any tool can say here is: it cannot help you.",
  },
];

/* ------------------------------------------------ TOOLS */

// Shared filter normalization. Unknown values fall back to defaults, and the filter that
// actually took effect is echoed back - otherwise a caller's typo silently yields an empty
// result with no explanation (a usability defect found by the matrix traverser).
function applyFilter(findings, args) {
  const effLayer = (typeof args.layer === "string" && (args.layer === "all" || LAYERS[args.layer]))
    ? args.layer : "all";
  const effSev = (typeof args.min_severity === "string" && args.min_severity in SEVERITY_ORDER)
    ? args.min_severity : "ok";
  const minSev = SEVERITY_ORDER[effSev];
  let out = findings;
  if (effLayer !== "all") out = out.filter((f) => f.layer === effLayer);
  out = out.filter((f) => SEVERITY_ORDER[f.severity] >= minSev);
  // The order is a contract, not an artifact of which auditor happened to push first.
  //
  // Until the checks moved into the catalog this sorted by severity alone and left ties in
  // ASSEMBLY order -- so moving a check from one function to another silently changed where a
  // finding appeared while every one of its fields stayed identical. Severity is what a reader
  // scans first, layer is how the report is grouped, and the id breaks the remaining ties;
  // together they make the order reproducible from the findings themselves.
  out.sort((a, b) =>
    (SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]) ||
    (layerRank(a.layer) - layerRank(b.layer)) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return { findings: out, layer: effLayer, min_severity: effSev };
}

/** Where a layer sits in the report. LAYERS is written in reading order, so its index is the rank. */
const LAYER_ORDER = Object.keys(LAYERS);
function layerRank(layer) {
  const i = LAYER_ORDER.indexOf(layer);
  return i < 0 ? LAYER_ORDER.length : i;
}

/**
 * Pick the target.
 *
 * An explicit argument always wins. Otherwise AIKAWAMEI_TARGET sets the build default, which
 * is what makes per-target artifacts possible without forking the code: the tor launcher
 * exports AIKAWAMEI_TARGET=tor and the firefox launcher exports firefox, and both run the
 * same core. Only when neither is present does auto-detection apply, preferring Tor
 * Browser and falling back to Firefox.
 */
function resolveTarget(requested, torInstalls, ffProfiles) {
  if (requested === "tor" || requested === "firefox") return requested;
  const fromEnv = process.env.AIKAWAMEI_TARGET;
  if (fromEnv === "tor" || fromEnv === "firefox") return fromEnv;
  if (torInstalls.length > 0) return "tor";
  if (ffProfiles.length > 0) return "firefox";
  return "tor";
}

/** proxy argument semantics: undefined = auto, false/"none" = force direct, else the URL. */
function resolveProxyArg(p) {
  return p === undefined ? undefined : (p === false || p === "none" ? null : p);
}

const tallyOf = (findings) => {
  const t = {};
  for (const f of findings) t[f.severity] = (t[f.severity] ?? 0) + 1;
  return t;
};

/**
 * Local Firefox version: the installed application first, then what the profile last used
 * with. compatibility.ini writes "142.0_20250901123456/20250901123456", so the version has
 * to be cut at the underscore.
 */
function resolveFirefoxLocal(explicitInstall, profiles) {
  const app = findFirefoxApplication(explicitInstall);
  if (app) return { version: app.version, from: `application.ini at ${app.dir}` };
  const p = profiles.find((x) => x.is_default) ?? profiles[0];
  const lv = p?.last_version ?? null;
  if (lv) return {
    version: String(lv).split("_")[0],
    from: `compatibility.ini in ${p.profile_dir} (the version this profile was last used with, not necessarily what is installed)`,
  };
  return { version: null, from: null };
}

/* ------------------------------------------------ built-in probe context */

// probeInputsFor and statfsTypeOf live in shared.mjs: the Firefox auditor needs them too, and a
// caller that uses the library directly must get the same finding set the CLI does.

/**
 * The conformance and facts blocks.
 *
 * Both are built from the UNFILTERED observations. Facts are judgement-free and are meant to
 * answer "what did it read", so a caller asking for warnings only must not silently lose the
 * informational observations; and conformance must catch a catalog mismatch even when the
 * offending finding was filtered out of the reply.
 */
function conformanceAndFacts(observations, target, layer) {
  const { facts, sources } = factsFrom(observations, { layer });
  return {
    facts,
    facts_schema: FACTS_SCHEMA,
    facts_sources: sources,
    checks: {
      schema: CHECKS_SCHEMA,
      catalog_version: CATALOG_VERSION,
      catalog_digest: catalogDigest(),
      declared: CHECK_CATALOG.length,
      ...validateFindings(observations, { target }),
    },
  };
}

const TOOLS = [
  {
    name: "aikawamei_env", operations: OPS_STATIC,
    description:
      "Probe the runtime environment and discover every supported target on this machine: Tor Browser installs and " +
      "Firefox profiles. Read-only, no network. Run this first to obtain the install or profile path the other tools take.",
    inputSchema: {
      type: "object",
      properties: {
        install: { type: "string", description: "Optional: a Tor Browser install root to use directly" },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      return {
        schema: ENV_SCHEMA,
        tool_version: VERSION,
        environment: detectEnvironment(),
        targets: {
          tor: { found: torInstalls.length, installs: torInstalls },
          firefox: { found: ffProfiles.length, profiles: ffProfiles },
        },
        // The emblem travels with the tool as a sealed statement of what it is named after. It
        // is reported here because this is the tool that answers what is running, and it is
        // reported as structure only: this process holds no key and must not imply otherwise.
        emblem: inspectEmblem(readShippedEmblem()),
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };
    },
  },

  {
    name: "aikawamei_audit", operations: OPS_STATIC,
    description:
      "Full static posture audit of one target across five layers. For Tor Browser: build versions, bridges/pluggable " +
      "transports/uTLS/domain fronting, onion client authorization and service keys, state guard residue and descriptor " +
      "caches, disk location and stray copies. For Firefox: application version, proxy and DoH and content-blocking " +
      "prefs, saved logins and key material, history and cookies and site data and telemetry ID and account linkage, " +
      "profile location and persistence. Reads files only; launches nothing and uses no network. " +
      "Severity is calibrated per target rather than shared: Tor Browser is hardened by default, so retained state there " +
      "is a deviation and is reported as a warning, whereas a plain Firefox profile retains data by design, so only " +
      "cross-machine identity linkage and credential exposure earn a warning. " +
      "Findings are grouped by layer and sorted by severity. A clean audit is not safety - see boundary_notice.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          enum: ["auto", "tor", "firefox"],
          description: "Which target to audit; auto prefers Tor Browser and falls back to Firefox",
        },
        install: { type: "string", description: "Tor Browser install root; auto-discovered when omitted" },
        profile: { type: "string", description: "Firefox profile directory; defaults to the profile marked default, else the first one found" },
        layer: {
          type: "string",
          enum: ["all", "build", "transport", "crypto", "metadata", "endpoint"],
          description: "Restrict output to one layer; defaults to all",
        },
        min_severity: {
          type: "string",
          enum: ["ok", "info", "warn", "critical"],
          description: "Minimum severity to report; defaults to ok (everything, including positive findings)",
        },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      const target = resolveTarget(args.target, torInstalls, ffProfiles);

      if (target === "tor") {
        if (torInstalls.length === 0) {
          return {
            schema: AUDIT_SCHEMA,
            tool_version: VERSION,
            target,
            error: "No Tor Browser install found. Use aikawamei_env to see the scan scope, or pass an explicit install path.",
            boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
          };
        }
        const inst = torInstalls[0];
        const torrc = parseTorrc(readText(path.join(inst.data_dir, "torrc")));
        const defaults = parseTorrc(readText(path.join(inst.data_dir, "torrc-defaults")));
        const prefs = parsePrefs(readText(path.join(inst.profile_dir, "prefs.js")));
        const stateText = readText(path.join(inst.data_dir, "state"));
        const merged = {
          entries: { ...defaults.entries, ...torrc.entries },
          order: [...defaults.order, ...torrc.order],
        };
        // One probe context for the whole audit: the built-in checks are split across three layer
        // functions, and building the context in each would read the mount table and stat the
        // volume three times to answer the same question.
        const authDir = (merged.entries.ClientOnionAuthDir ?? [])[0];
        const probeBases = {
          install_root: inst.root,
          data_dir: inst.data_dir,
          profile_dir: inst.profile_dir,
          keys_dir: path.join(inst.data_dir, "keys"),
        };
        // auth_dir is present only when the torrc names it. The onion-auth checks both key off it,
        // so whether it is configured is answered in exactly one place rather than in two that
        // could disagree with each other.
        if (authDir) probeBases.auth_dir = authDir;
        const pctx = probeInputsFor(inst.root, probeBases, { entries: merged.entries, prefs });

        const observations = [
          ...auditBuild(inst, stateText),
          ...auditTransport(merged.entries, prefs, pctx),
          ...auditCrypto(merged.entries, inst, pctx),
          ...auditMetadata(inst, pctx),
          ...auditEndpoint(inst, pctx),
        ];
        const f = applyFilter(observations, args);
        return {
          schema: AUDIT_SCHEMA,
          tool_version: VERSION,
          target,
          install: inst,
          applied_filter: { layer: f.layer, min_severity: f.min_severity },
          tally: tallyOf(f.findings),
          findings: f.findings,
          ...conformanceAndFacts(observations, "tor", f.layer),
          torrc_effective: {
            UseBridges: merged.entries.UseBridges ?? null,
            Bridge_count: (merged.entries.Bridge ?? []).length,
            ClientOnionAuthDir: merged.entries.ClientOnionAuthDir ?? null,
            ClientTransportPlugin_count: (merged.entries.ClientTransportPlugin ?? []).length,
            SocksPort: merged.entries.SocksPort ?? null,
            ControlPort: merged.entries.ControlPort ?? null,
          },
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }

      // ---- Firefox ----
      if (ffProfiles.length === 0) {
        return {
          schema: AUDIT_SCHEMA,
          tool_version: VERSION,
          target,
          error: "No Firefox profile found. Use aikawamei_env to see the scan scope, or pass an explicit profile path.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }
      let profileDir = args.profile;
      if (typeof profileDir !== "string" || !profileDir.trim()) {
        profileDir = pickDefaultProfile(ffProfiles).profile_dir;
      }
      const observations = [
        ...auditFirefoxProfile(profileDir, { allProfiles: ffProfiles }),
      ];
      const f = applyFilter(observations, args);
      return {
        schema: AUDIT_SCHEMA,
        tool_version: VERSION,
        target,
        profile: profileDir,
        profiles_found: ffProfiles.length,
        applied_filter: { layer: f.layer, min_severity: f.min_severity },
        tally: tallyOf(f.findings),
        findings: f.findings,
        ...conformanceAndFacts(observations, "firefox", f.layer),
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };
    },
  },

  {
    name: "aikawamei_version", operations: OPS_LOOKUP,
    description:
      "Check version freshness for the selected target. For Tor Browser it reads the local tbb_version.json and compares " +
      "it against Tor Project's official release metadata; for Firefox it reads the installed application (falling back to " +
      "the version the profile was last used with) and compares it against Mozilla's published current versions, honouring " +
      "the release / esr / beta / nightly channel. This is the only network call the tool makes; it reads public version " +
      "information only and never touches the audited application. It uses the local proxy automatically (environment " +
      "variables or the Windows system proxy); override with the proxy argument.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          enum: ["auto", "tor", "firefox"],
          description: "Which target to check; auto prefers Tor Browser and falls back to Firefox",
        },
        install: { type: "string", description: "Tor Browser install root, or a Firefox program directory; auto-discovered when omitted" },
        online: { type: "boolean", description: "Opt in to a single network request that asks a public endpoint for the current version. Off by default, so the default posture of this tool is offline; the local version is always reported." },
        proxy: { type: "string", description: 'Proxy URL (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:1080). Auto-detected when omitted; pass "none" to force a direct connection.' },
      },
    },
    async execute(args = {}) {
      const torInstalls = discoverInstalls(args.install);
      const ffProfiles = discoverFirefoxProfiles();
      const target = resolveTarget(args.target, torInstalls, ffProfiles);
      const result = {
        schema: VERSION_SCHEMA,
        tool_version: VERSION,
        target,
        installed: null,
        channel: null,
        latest: null,
        verdict: "unknown",
        // The notice describes THIS call, not what the tool is capable of. It starts at the weakest
        // class and is raised at the one place a request is actually made, so a default call -- which
        // makes no request -- carries the unconditional "never touches the network" sentence rather
        // than one with an exception it did not use.
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };

      if (target === "tor") {
        const inst = torInstalls[0] ?? null;
        result.installed = inst?.tor_browser_version ?? null;
        result.channel = inst?.channel ?? "release";
        result.firefox_base = inst?.firefox_version ?? null;
        if (args.online !== true) {
          result.note = "No version lookup was performed: it is opt-in and was not requested. The installed version above is local.";
          return result;
        }
        const url = TOR_VERSION_ENDPOINTS[result.channel] ?? TOR_VERSION_ENDPOINTS.release;
        // Raised before the request rather than after it: if the request throws, a request was still
        // made, and a notice that only admitted it on success would be false exactly when it matters.
        result.boundary_notice = NOTICE_LOOKUP;
        result.operations = OPS_LOOKUP;
        try {
          const { json: j, via } = await httpsGetJson(url, { timeoutMs: 15000, proxy: resolveProxyArg(args.proxy) });
          result.latest = j.version ?? null;
          result.source = url;
          result.via = via;
          result.proxy_detected = detectProxy();
          if (result.installed && result.latest) {
            const c = cmpVer(result.installed, result.latest);
            result.verdict = c === 0 ? "current" : c < 0 ? "outdated" : "ahead";
            result.delta = c < 0 ? `${result.installed} -> ${result.latest}` : null;
          }
        } catch (e) {
          result.verdict = "check-failed";
          result.error = String(e.message ?? e);
          result.source = url;
        }
        return result;
      }

      // ---- Firefox ----
      const local = resolveFirefoxLocal(args.install, ffProfiles);
      result.installed = local.version;
      result.channel = "release";
      result.local_source = local.from;
      if (args.online !== true) {
        result.note = "No version lookup was performed: it is opt-in and was not requested. The installed version above is local.";
        return result;
      }
      result.boundary_notice = NOTICE_LOOKUP;
      result.operations = OPS_LOOKUP;
      try {
        const { json: j, via } = await httpsGetJson(FIREFOX_VERSION_ENDPOINT, { timeoutMs: 15000, proxy: resolveProxyArg(args.proxy) });
        result.latest = j[FIREFOX_CHANNEL_KEYS[result.channel]] ?? null;
        result.available_channels = Object.fromEntries(
          Object.entries(FIREFOX_CHANNEL_KEYS).map(([k, key]) => [k, j[key] ?? null]));
        result.source = FIREFOX_VERSION_ENDPOINT;
        result.via = via;
        result.proxy_detected = detectProxy();
        if (result.installed && result.latest) {
          const c = cmpVer(result.installed, result.latest);
          result.verdict = c === 0 ? "current" : c < 0 ? "outdated" : "ahead";
          result.delta = c < 0 ? `${result.installed} -> ${result.latest}` : null;
        }
      } catch (e) {
        result.verdict = "check-failed";
        result.error = String(e.message ?? e);
        result.source = FIREFOX_VERSION_ENDPOINT;
      }
      return result;
    },
  },
  {
    name: "aikawamei_layer_assess", operations: OPS_STATIC,
    description:
      "Layered threat assessment. Given scenario characteristics, decide which layer of protection is needed, recommend a delivery channel, " +
      "and explicitly list what the method does NOT cover. This tool is built to say no: it refuses to manufacture false confidence. " +
      "Whenever a scenario lands in the metadata or endpoint layer it points at the real answer (mixnet / environment isolation / no technical solution) " +
      "rather than piling on more onion configuration.",
    inputSchema: {
      type: "object",
      properties: {
        content_sensitive: { type: "boolean", description: "Does the content itself need protection (what happens if it is read)" },
        metadata_sensitive: { type: "boolean", description: "Does the fact of communicating need protection (what happens if who-talks-to-whom is known)" },
        realtime: { type: "boolean", description: "Is realtime / near-realtime round-trip required" },
        counterpart_capability: {
          type: "string",
          enum: ["email-only", "can-install-tools", "signal-capable", "tor-capable"],
          description: "The upper bound of the counterpart's tooling - this usually caps the whole design",
        },
        must_leave_no_third_party_copy: { type: "boolean", description: "Must no third party retain a copy" },
        endpoint_shared_or_seizable: { type: "boolean", description: "Can the endpoint be accessed by others or seized" },
      },
    },
    async execute(args = {}) {
      const content = args.content_sensitive === true;
      const meta = args.metadata_sensitive === true;
      const realtime = args.realtime === true;
      const cap = args.counterpart_capability ?? "email-only";
      const noCopy = args.must_leave_no_third_party_copy === true;
      const seizable = args.endpoint_shared_or_seizable === true;

      const warnings = [];
      const does_not_cover = [];
      const steps = [];

      // -- core discipline: layer-mismatch detection --
      if (content && !meta) {
        steps.push("Content layer only: ordinary end-to-end encryption suffices (age / 7z+AES / Proton encrypted email).");
        warnings.push("Do not pile high-risk tradecraft onto a purely content-sensitive scenario - that itself is the most conspicuous signature.");
      }
      if (meta) {
        warnings.push("You declared metadata sensitivity. Note: content encryption helps the metadata layer by roughly zero.");
        steps.push("The metadata layer needs: a mixnet (Nym) or a metadata-hiding messenger (SimpleX / Cwtch), not a wrapper around email.");
      }
      if (meta && realtime) {
        warnings.push(
          "[HARD CONFLICT] Realtime round-trips directly oppose metadata protection. Realtime communication couples both endpoints' timing tightly, " +
          "which is the perfect material for end-to-end timing correlation. If metadata protection is genuinely required, you must accept asynchrony " +
          "(mailbox / dead-drop model, where the receiver fetches on its own schedule).");
        steps.push("Convert realtime into asynchronous: use a drop point / mailbox model so that send and fetch are decoupled in time.");
      }
      if (cap === "email-only") {
        warnings.push("The counterpart only has email - this caps the design hard: PGP, OnionShare and Tor are all unusable for an ordinary mailbox user.");
        steps.push("What email can realistically carry: Proton/Tutanota encrypted-to-external mail (zero tooling for them), or a password-protected archive with the passphrase sent out of band.");
      }
      if (noCopy) {
        steps.push("No third-party copy: OnionShare (ephemeral onion, file stays on your machine) or send directly over Signal/SimpleX, bypassing email entirely.");
        if (cap === "email-only") warnings.push('But the counterpart is email-only, so "no third-party copy" is not achievable - re-evaluate their capability.');
      }
      if (seizable) {
        warnings.push(
          "The endpoint may be accessed or seized. This is the layer cryptography cannot reach: a coerced endpoint, a keylogger, " +
          "and already-decrypted copies cannot be fixed by any transport-layer design.");
        steps.push("The endpoint layer only yields to environment isolation (Qubes+Whonix / an amnesic OS) and full-disk encryption - and you must assume that a seized device means disclosed content.");
      }

      // -- disclaimer that must always be present --
      does_not_cover.push("Traffic correlation and timing analysis (the adversary only needs to line up entry and exit times; reading the content is unnecessary)");
      does_not_cover.push("Endpoint compromise: malware, keyloggers, device seizure");
      does_not_cover.push("What happens after decryption: the recipient read it, kept a copy, talked about it, met someone - the most common failure in public cases");
      does_not_cover.push("People (the social layer has no technical solution)");

      const recommended_channel =
        !content && !meta ? "No special channel needed (ordinary email is fine)"
        : meta && cap === "tor-capable" ? "Nym mixnet, or SimpleX / Cwtch; email for notification only"
        : meta ? "Prefer SimpleX (no user identifiers); if the counterpart only uses email, email transport is acceptable but must be asynchronous"
        : noCopy ? "OnionShare, or Signal / SimpleX"
        : cap === "email-only" ? "Proton / Tutanota encrypted-to-external mail, passphrase sent out of band"
        : "Signal / SimpleX with an encrypted attachment, passphrase sent out of band";

      return {
        schema: ASSESS_SCHEMA,
        tool_version: VERSION,
        input: { content_sensitive: content, metadata_sensitive: meta, realtime, counterpart_capability: cap,
                 must_leave_no_third_party_copy: noCopy, endpoint_shared_or_seizable: seizable },
        layer_model: LAYER_MODEL,
        recommended_channel,
        steps,
        warnings,
        does_not_cover,
        verdict:
          !content && !meta && !seizable && !noCopy
            ? "No sensitivity was declared - no special tradecraft is warranted. Applying high-risk tradecraft to low-sensitivity content is itself the most conspicuous signature."
          : meta || seizable
            ? 'This scenario cannot be solved by "configuring Tor/encryption better". Follow the warnings above to the layer that actually addresses it.'
            : "This scenario is a content-layer problem; ordinary encryption is enough and no high-intensity tradecraft is needed.",
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };
    },
  },

  {
    name: "aikawamei_checks", operations: OPS_STATIC,
    description:
      "Query the declared check surface: every check this build performs, what each one reads, what each one explicitly does NOT " +
      "cover, and the severities it is allowed to report. Pure data - it reads no files and audits nothing. " +
      "Use it before an audit to find out whether this tool can answer your question at all, and to read the per-check limits " +
      "that the shared boundary notice deliberately does not enumerate.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", enum: ["tor", "firefox"], description: "Restrict to the checks one target produces" },
        layer: {
          type: "string",
          enum: ["all", "build", "transport", "crypto", "metadata", "endpoint"],
          description: "Restrict to one layer; defaults to all",
        },
        id: { type: "string", description: "Look up a single check by its id instead of listing" },
      },
    },
    async execute(args = {}) {
      const head = {
        schema: CHECKS_SCHEMA,
        tool_version: VERSION,
        catalog_version: CATALOG_VERSION,
        catalog_digest: catalogDigest(),
      };
      if (typeof args.id === "string" && args.id.trim()) {
        const wanted = args.id.trim();
        const one = checkById(wanted);
        return {
          ...head,
          id: wanted,
          found: one !== null,
          check: one,
          note: one ? null : "No check carries that id. Call without id to list the surface.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }
      return { ...head, ...checksFor({ target: args.target, layer: args.layer }), boundary_notice: NOTICE_STATIC, operations: OPS_STATIC };
    },
  },

  {
    name: "aikawamei_baseline", operations: OPS_STATIC,
    description:
      "Posture baseline and drift: posture at rest is one question, and posture DRIFT is a different one that a single audit " +
      "cannot answer. mode=capture records the current audit as a baseline - one fingerprint per check, never the evidence " +
      "itself, so a stored baseline cannot become a tidy copy of the residue this tool tells you not to keep. " +
      "mode=diff compares a stored baseline against a fresh audit and reports what appeared, disappeared, changed, or moved severity. " +
      "Stateless by design: nothing is written anywhere and the caller keeps the baseline. " +
      "A diff refuses rather than guesses when the records describe different subjects or targets, or when the check catalog moved.",
    inputSchema: {
      type: "object",
      properties: {
        mode: {
          type: "string",
          enum: ["capture", "diff"],
          description: "capture a baseline (default), or diff a stored one against the current state",
        },
        baseline: { type: "object", description: "A previously captured baseline; for mode=diff. A capture response is accepted as well as a bare record, so the file written by redirecting a capture can be passed straight back." },
        baseline_path: { type: "string", description: "Path to a baseline JSON file to read instead of passing it inline; a capture response or a bare record both work" },
        target: { type: "string", enum: ["auto", "tor", "firefox"], description: "Which target to audit; auto prefers Tor Browser" },
        install: { type: "string", description: "Tor Browser install root; auto-discovered when omitted" },
        profile: { type: "string", description: "Firefox profile directory; defaults to the profile marked default" },
      },
    },
    async execute(args = {}) {
      const auditTool = TOOLS.find((t) => t.name === "aikawamei_audit");
      const head = { schema: BASELINE_REPORT_SCHEMA, tool_version: VERSION };
      const wantDiff = args.mode === "diff";

      // Resolve and check what the caller handed us BEFORE auditing.
      //
      // Two reasons. The first is that a malformed baseline is a caller error, and reporting it
      // should not depend on whether this machine happens to have a target worth auditing -- the
      // first version audited first, so on a machine with neither Tor Browser nor Firefox a bad
      // baseline was reported as "no install found" instead. The second is simply that there is
      // no reason to do the work when the input is already known to be unusable.
      let base = null;
      if (wantDiff) {
        base = unwrapBaseline(args.baseline);
        if ((base === undefined || base === null) && typeof args.baseline_path === "string" && args.baseline_path.trim()) {
          base = unwrapBaseline(readJson(args.baseline_path.trim()));
          if (base === null) {
            return {
              ...head, mode: "diff", verdict: "invalid-baseline", comparable: false,
              reason: `Could not read a JSON baseline from ${args.baseline_path.trim()}.`,
              boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
            };
          }
        }
        if (base === undefined || base === null) {
          return {
            ...head, mode: "diff", verdict: "no-baseline", comparable: false,
            reason: "mode=diff needs a baseline: pass the captured object as `baseline`, or a file path as `baseline_path`.",
            boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
          };
        }
        const check = validateBaseline(base);
        if (!check.ok) {
          return {
            ...head, mode: "diff", verdict: "invalid-baseline", comparable: false,
            reason: check.reason,
            boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
          };
        }
      }

      // The baseline always records the FULL audit, never a filtered view. Capturing through a
      // layer or severity filter would make the same machine produce different fingerprints
      // depending on how the caller happened to ask, and a later diff would read that as drift.
      const audit = await auditTool.execute({ target: args.target, install: args.install, profile: args.profile });

      if (audit.error) {
        return { ...head, mode: wantDiff ? "diff" : "capture", error: audit.error, boundary_notice: NOTICE_STATIC, operations: OPS_STATIC };
      }

      const current = baselineFrom(audit);

      if (!wantDiff) {
        return {
          ...head,
          mode: "capture",
          baseline: current,
          audit_summary: {
            target: current.target,
            subject: current.subject,
            tally: current.tally,
            checks_recorded: current.check_count,
          },
          note:
            "Store this wherever you like and hand it back with mode=diff later. It contains fingerprints only: " +
            "no paths, no guard names, no key filenames, no evidence.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }

      return { ...head, mode: "diff", ...diffBaselines(base, current), boundary_notice: NOTICE_STATIC, operations: OPS_STATIC };
    },
  },
  {
    name: "aikawamei_handoff", operations: OPS_STATIC,
    description:
      "Scan a directory that is about to be handed to someone else and report what would travel with it: file names that look like " +
      "key material or credentials, editor and OS residue, version-control and build artefacts, and whether OnionShare is installed " +
      "to send it. Static and read-only exactly like the audit: it reads names and sizes, never file contents, and never uses the " +
      "network. When a Tor Browser install is present its onion client authorization state is included, because that is the other " +
      "half of preparing a delivery -- which answers who can reach the service the package is being sent over.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "The directory about to be handed over" },
        tor_install: {
          type: "string",
          description: "Optional: a Tor Browser install root to use for the onion authorization part, instead of the one that would be discovered",
        },
        layer: {
          type: "string",
          enum: ["all", "build", "transport", "crypto", "metadata", "endpoint"],
          description: "Restrict to one layer; defaults to all",
        },
        min_severity: {
          type: "string",
          enum: ["ok", "info", "warn", "critical"],
          description: "Only report findings at or above this severity; defaults to ok, which reports everything",
        },
      },
      required: ["path"],
    },
    async execute(args = {}) {
      const target = typeof args.path === "string" ? args.path : "";
      if (!target) {
        return {
          schema: HANDOFF_SCHEMA,
          tool_version: VERSION,
          error: "A path is required: this tool reports on one directory.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }
      let isDir = false;
      try { isDir = fs.statSync(target).isDirectory(); } catch { isDir = false; }
      if (!isDir) {
        return {
          schema: HANDOFF_SCHEMA,
          tool_version: VERSION,
          directory: target,
          error: "Not a directory, or not one this process can read.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }

      // The Tor install is resolved the same way the audit resolves one, and its only job here is
      // to answer the onion-authorization question. With none present those checks stay silent
      // rather than reporting an absence they cannot establish -- and the response names whichever
      // install was used, so nothing about the report depends on a discovery the caller cannot see.
      const explicit = typeof args.tor_install === "string" && args.tor_install ? args.tor_install : null;
      const inst = discoverInstalls(explicit)[0] ?? null;

      const observations = handoffFindings(target, inst);
      const f = applyFilter(observations, args);
      return {
        schema: HANDOFF_SCHEMA,
        tool_version: VERSION,
        directory: target,
        tor_install: inst ? inst.root : null,
        applied_filter: { layer: f.layer, min_severity: f.min_severity },
        tally: tallyOf(f.findings),
        findings: f.findings,
        ...conformanceAndFacts(observations, "handoff", f.layer),
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };
    },
  },
  {
    name: "aikawamei_sessions", operations: OPS_WRITES,
    description:
      "Report the session material the browser-automation toolchains left on this machine: plaintext session exports, cookie jars, " +
      "HTTP archives, browser profile stores, automation profile directories and trace artifacts, under roots derived from the " +
      "environment or named explicitly. Static and read-only exactly like the audit: it reads names and sizes, never a file's " +
      "contents, and never uses the network. Each hit says whether it sits inside a git working tree. Which paths git ignores, and " +
      "which were ever committed, is reported as undetermined together with the command that answers it, because answering it would " +
      "mean running git -- and a tool that opens a credential store in order to describe it has copied the credential.",
    inputSchema: {
      type: "object",
      properties: {
        roots: {
          type: "array",
          items: { type: "string" },
          description:
            "Directories to scan. Omit to use the roots derived from the environment: the user profile, the application-data " +
            "directories, the temporary directory, and the working directory.",
        },
        vault: {
          type: "string",
          description:
            "Optional: append one record of this run to a tamper-evident chain at this path. Nothing is written unless this is " +
            "given -- the other tools here are read-only, and one that wrote on every call would break the notice it carries. The " +
            "record always holds counts; it holds the paths only inside a sealed payload, and only when AIKAWAMEI_VAULT_PASSPHRASE " +
            "is set in the environment (an environment variable rather than an argument, because arguments are visible in the " +
            "process list and in shell history).",
        },
        scope: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional: the roots you claim as your own, as a repeated flag. Given one it becomes an allowlist, and any root outside " +
            "it is refused rather than scanned. Omit it and the default rules apply instead: a network path, or a profile directory " +
            "belonging to a different user, is refused. Nothing here can establish who owns a path -- a scope is a declaration by the " +
            "operator, which is why the response states that and records every refusal.",
        },
        layer: {
          type: "string",
          enum: ["all", "build", "transport", "crypto", "metadata", "endpoint"],
          description: "Restrict to one layer; defaults to all",
        },
        min_severity: {
          type: "string",
          enum: ["ok", "info", "warn", "critical"],
          description: "Only report findings at or above this severity; defaults to ok, which reports everything",
        },
      },
    },
    async execute(args = {}) {
      // The roots are derived here rather than inside the scan so that the response can name each
      // one it looked at, including the ones that turned out not to exist. A root that is absent
      // is a fact about the machine, not a reason to leave it out of the report.
      const requested = Array.isArray(args.roots) && args.roots.length ? args.roots : defaultSessionRoots();
      const { scanned, skipped } = planSessionRoots(requested);

      // The scope decides what may be READ, before anything is opened. A declared scope is an
      // allowlist and everything outside it is refused; with no declaration the default rules refuse
      // the two shapes that usually mean someone else's data -- a network path, and a profile
      // belonging to a different user. A refused root is not scanned and is named in the response,
      // because a refusal a reader cannot see is a silent hole.
      const scope = Array.isArray(args.scope) && args.scope.length ? declaredScope(args.scope) : defaultScope();
      const { allowed: scopedRoots, refused } = classifyTargets(scanned, scope);

      const roots = [];
      const observations = [];
      for (const root of scopedRoots) {
        let isDir = false;
        try { isDir = fs.statSync(root).isDirectory(); } catch { isDir = false; }
        if (!isDir) {
          roots.push({ root, exists: false, findings: 0, scanned_entries: 0, truncated: false, depth_limited: false });
          continue;
        }
        const s = scanSessionRoot(root);
        roots.push({ root, exists: true, findings: s.findings.length, scanned_entries: s.scanned_entries, truncated: s.truncated, depth_limited: s.depth_limited });
        observations.push(...s.findings);
      }

      const f = applyFilter(observations, args);

      // An optional record of what this run saw, appended to a tamper-evident chain.
      //
      // Writing is DELIBERATELY not automatic. Every other tool here is read-only, and one that
      // silently wrote a file on every call would break the promise the boundary notice makes. The
      // caller names a chain or nothing is written.
      //
      // Two shapes, and the difference is the point. With no passphrase the record carries COUNTS
      // and nothing else: it proves the run happened and nothing about who it was about. With a
      // passphrase, the paths go inside the sealed payload -- so the record is confidential as well
      // as tamper-evident, and the cleartext still names no path. Sealing here is not a display
      // preference: the paths in a sessions scan belong to whoever's profile they are.
      const vaultPath = typeof args.vault === "string" && args.vault ? args.vault : null;
      const passphrase = process.env.AIKAWAMEI_VAULT_PASSPHRASE ?? null;
      let vault = null;
      if (vaultPath) {
        const note = `${roots.length} root(s) scanned, ${refused.length} refused, ${f.findings.length} finding(s), ${observations.length} observation(s)`;
        const sealed = passphrase
          ? sealValue(passphrase, {
              scope: { mode: scope.mode, source: scope.source, declared_roots: scope.mode === "declared" ? scope.roots : [] },
              refused,
              roots: roots.map((r) => ({ root: r.root, exists: r.exists, truncated: r.truncated, depth_limited: r.depth_limited })),
              findings: f.findings.map((x) => ({ id: x.id, severity: x.severity, entries: (x.evidence?.entries ?? []) })),
            })
          : null;
        try {
          const appended = appendRecord(vaultPath, { kind: "sessions-scan", note, sealed });
          vault = { path: vaultPath, length: appended.length, hash: appended.hash, sealed: sealed !== null };
        } catch (e) {
          vault = { path: vaultPath, error: String((e && e.message) || e) };
        }
      }

      return {
        schema: SESSIONS_SCHEMA,
        tool_version: VERSION,
        roots,
        roots_skipped: skipped,
        scope: scopeReport(scope),
        refused,
        applied_filter: { layer: f.layer, min_severity: f.min_severity },
        tally: tallyOf(f.findings),
        findings: f.findings,
        ...conformanceAndFacts(observations, "sessions", f.layer),
        not_determined: SESSIONS_NOT_DETERMINED,
        ...(vaultPath ? { vault } : {}),
        boundary_notice: NOTICE_WRITES, operations: OPS_WRITES,
      };
    },
  },

  {
    name: "aikawamei_vault",
    operations: OPS_STATIC,
    description:
      "Verify a tamper-evident record produced by another tool, and report the length and head that a " +
      "later verification can be held to. The chain is hashed over the SEALED lines, so integrity can be " +
      "checked by someone who cannot read a single entry and without the passphrase. What it cannot see " +
      "is its own tail being cut: pass the length and head a previous verification reported and a " +
      "truncation is caught, which is why the receipt is returned rather than just a verdict.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "The record file to verify" },
        expect_length: { type: "integer", description: "Optional: the length a previous verification reported. A shorter file is then a detected truncation rather than a shorter file." },
        expect_head: { type: "string", description: "Optional: the head hash a previous verification reported" },
      },
      required: ["path"],
    },
    async execute(args = {}) {
      const target = typeof args.path === "string" ? args.path : "";
      const head = VAULT_SCHEMA;
      if (!target) {
        return {
          schema: head, tool_version: VERSION,
          error: "A path is required: this tool verifies one record file.",
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }
      const expectations = {};
      if (Number.isInteger(args.expect_length)) expectations.expectLength = args.expect_length;
      if (typeof args.expect_head === "string" && args.expect_head) expectations.expectHead = args.expect_head;
      let result;
      try {
        result = verifyFile(target, expectations);
      } catch (e) {
        return {
          schema: head, tool_version: VERSION, path: target,
          error: String((e && e.message) || e),
          boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
        };
      }
      return {
        schema: head,
        tool_version: VERSION,
        path: target,
        ...result,
        // Stated here rather than left to the reader: a receipt that is not kept cannot detect a
        // tail that was cut, and the length and head above are the receipt.
        receipt: { length: result.length, head: result.head },
        does_not_cover: "Who wrote it, or whether an entry was removed from the end before you kept a receipt. Nothing here signs, and a chain cannot see its own tail being cut.",
        boundary_notice: NOTICE_STATIC, operations: OPS_STATIC,
      };
    },
  },

  {
    name: "aikawamei_triage",
    operations: OPS_WRITES,
    description:
      "Answer a narrow question about this machine: is there a foothold, and where. Reads five artefact surfaces that are FILES -- WER " +
      "crash reports, Prefetch, the two Startup folders, scheduled-task XML, and executables under the locations anything can write to " +
      "-- aligns them in time, and reports the windows where several mechanisms agree. Read-only and static: nothing is executed, and " +
      "no file is opened beyond reading its bytes. The registry surfaces that would answer the rest -- Run and RunOnce, the service " +
      "table, Amcache and ShimCache, Defender's detection history -- are reported as undetermined with the command that answers each, " +
      "because reaching them means running a program and this tool runs nothing. A negative answer here does NOT mean the machine is clean.",
    inputSchema: {
      type: "object",
      properties: {
        windows_root: { type: "string", description: "The Windows directory. Defaults to %SystemRoot%; with neither, the two surfaces below it are reported as not looked at rather than guessed at." },
        user_root: { type: "string", description: "The user profile directory. Defaults to %USERPROFILE%." },
        app_data: { type: "string", description: "The roaming application-data directory. Defaults to %APPDATA%, and one of the two Startup folders is under it." },
        local_app_data: { type: "string", description: "The local application-data directory. Defaults to %LOCALAPPDATA%; the WER reporting queues are under it." },
        program_data: { type: "string", description: "The shared application-data directory. Defaults to %ProgramData%, and the all-users Startup folder is under it." },
        writable_roots: { type: "array", items: { type: "string" }, description: "Optional: where to look for executables. Defaults to the two application-data directories." },
        window_minutes: { type: "integer", description: "The width of a correlation window in minutes; defaults to 60." },
        min_cluster: { type: "integer", description: "How many entries a window needs before it is reported; defaults to 3, and it must always span more than one source." },
        timeline_limit: { type: "integer", description: "How many timeline entries to return, most recent first; defaults to 60. The total is reported beside it, so a bounded answer never reads as a complete one." },
        scope: { type: "array", items: { type: "string" }, description: "Optional: the roots you claim as your own. The system paths this tool reads are inside the default scope; a narrow declaration will refuse them, which the response reports rather than hides." },
        vault: { type: "string", description: "Optional: append one record of this run to a tamper-evident chain at this path, sealed when AIKAWAMEI_VAULT_PASSPHRASE is set. Nothing is written unless this is given." },
      },
    },
    async execute(args = {}) {
      const env = process.env;
      const io = realTriageIo();
      const pick = (v, fallback) => (typeof v === "string" && v ? v : (fallback || null));
      const windowsRoot = pick(args.windows_root, env.SystemRoot || env.windir);
      const userRoot = pick(args.user_root, env.USERPROFILE || env.HOME);
      const appData = pick(args.app_data, env.APPDATA);
      const localAppData = pick(args.local_app_data, env.LOCALAPPDATA);
      const programData = pick(args.program_data, env.ProgramData);

      // Each surface is named with the path it was read from, so a response with nothing in it can be
      // told apart from a response that never looked.
      const wanted = [
        { name: "wer", path: localAppData ? path.join(localAppData, "Microsoft", "Windows", "WER") : null, read: (p, b) => readWerReports(io, p, { budget: b }) },
        { name: "prefetch", path: windowsRoot ? path.join(windowsRoot, "Prefetch") : null, read: (p, b) => readPrefetch(io, p, { budget: b }) },
        { name: "startup", path: appData ? path.join(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup") : null, read: (p) => readStartupFolders(io, [p, programData ? path.join(programData, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp") : null]) },
        { name: "tasks", path: windowsRoot ? path.join(windowsRoot, "System32", "Tasks") : null, read: (p, b) => readScheduledTasks(io, p, { budget: b }) },
        { name: "writable", path: localAppData, read: (p, b) => readUserWritableExecutables(io, args.writable_roots?.length ? args.writable_roots : [localAppData, appData].filter(Boolean), { budget: b }) },
      ];

      // The scope guard runs before anything is read, on every path including the system ones.
      const scope = Array.isArray(args.scope) && args.scope.length ? declaredScope(args.scope) : defaultScope();
      const candidates = wanted.map((w) => w.path).filter(Boolean);
      const { refused } = classifyTargets(candidates, scope);
      const refusedSet = new Set(refused.map((r) => r.target));

      const surfaces = [];
      const entries = [];
      for (const w of wanted) {
        if (!w.path) { surfaces.push({ name: w.name, path: null, read: false, reason: "no path for this surface on this machine" }); continue; }
        if (refusedSet.has(path.resolve(w.path))) { surfaces.push({ name: w.name, path: w.path, read: false, reason: "refused by the scope" }); continue; }
        if (!io.exists(w.path)) { surfaces.push({ name: w.name, path: w.path, read: false, reason: "not present" }); continue; }
        // A surface that stopped at its ceiling says so, because "4000 executables" read as a count
        // is a different claim from "4000 executables and then I stopped looking".
        const budget = { truncated: false };
        const got = w.read(w.path, budget);
        entries.push(...got);
        surfaces.push({ name: w.name, path: w.path, read: true, entries: got.length, truncated: budget.truncated });
      }

      const line = timelineOf(entries);
      const windowMs = (Number.isInteger(args.window_minutes) ? args.window_minutes : 60) * 60 * 1000;
      const minCluster = Number.isInteger(args.min_cluster) ? args.min_cluster : 3;
      const clusters = clustersOf(line, { windowMs, minEntries: minCluster });
      const findings = findingsFor(entries);
      if (clusters.length && !findings.some((f) => f.id === "triage-correlated-window")) {
        // findingsFor clusters with its own defaults; if the caller widened the window past what it
        // computed, the finding is added here so the response never contains a window it does not
        // also report as a finding.
        findings.push({
          id: "triage-correlated-window", layer: "endpoint", severity: "info",
          title: `Found ${clusters.length} window(s) where several kinds of artefact appear together`,
          detail: "Several mechanisms agreeing inside one window is the closest a read-only pass gets to a foothold being established. It is also what a software update looks like, which is why each window lists its pieces rather than a conclusion.",
          evidence: { clusters: clusters.slice(0, 4) },
          does_not_cover: "What happened in the window, or whether the pieces are related to each other at all.",
        });
      }

      const limit = Number.isInteger(args.timeline_limit) ? args.timeline_limit : 60;
      const recent = line.slice().reverse().slice(0, limit);

      const vaultPath = typeof args.vault === "string" && args.vault ? args.vault : null;
      const passphrase = process.env.AIKAWAMEI_VAULT_PASSPHRASE ?? null;
      let vault = null;
      if (vaultPath) {
        const note = `${surfaces.filter((s) => s.read).length} surface(s) read, ${line.length} artefact(s), ${clusters.length} window(s), ${findings.length} finding(s)`;
        const sealed = passphrase
          ? sealValue(passphrase, {
              scope: { mode: scope.mode, source: scope.source },
              refused,
              surfaces: surfaces.map((s) => ({ name: s.name, path: s.path, read: s.read, entries: s.entries ?? null })),
              findings: findings.map((f) => ({ id: f.id, severity: f.severity, evidence: f.evidence })),
            })
          : null;
        try {
          const appended = appendRecord(vaultPath, { kind: "triage-run", note, sealed });
          vault = { path: vaultPath, length: appended.length, hash: appended.hash, sealed: sealed !== null };
        } catch (e) {
          vault = { path: vaultPath, error: String((e && e.message) || e) };
        }
      }

      return {
        schema: TRIAGE_SCHEMA,
        tool_version: VERSION,
        surfaces,
        scope: scopeReport(scope),
        refused,
        timeline_total: line.length,
        timeline_returned: recent.length,
        timeline_truncated: recent.length < line.length,
        timeline: recent,
        clusters,
        tally: tallyOf(findings),
        findings,
        ...conformanceAndFacts(findings, "triage", "all"),
        not_readable: TRIAGE_NOT_READABLE,
        ...(vaultPath ? { vault } : {}),
        boundary_notice: NOTICE_WRITES, operations: OPS_WRITES,
      };
    },
  },

  {
    name: "aikawamei_collect",
    operations: OPS_WRITES,
    description:
      "Copy the artefacts a triage run found -- or any paths you name -- to a destination you name, most perishable first, " +
      "hashing each copy as it goes and writing a manifest that is a hash chain. THIS IS THE ONE TOOL HERE THAT WRITES, which is " +
      "why its notice says so: what it writes is a copy, and the original is never modified, moved or re-timestamped. It refuses " +
      "a destination that sits inside what is being collected, and refuses a file above its ceiling, recording both rather than " +
      "skipping them quietly. Collection runs most-perishable-first because the things about to be pruned are the things nobody " +
      "can collect later -- and the parts of that order it cannot reach (memory, live network state, the process table) are " +
      "listed with the instrument that answers each.",
    inputSchema: {
      type: "object",
      properties: {
        paths: { type: "array", items: { type: "string" }, description: "The files to copy. Feed it what aikawamei_triage reported, or name your own." },
        destination: { type: "string", description: "Where the copies go. Required: this tool writes, and it will not choose where. Refused if it sits inside anything named in sources." },
        sources: { type: "array", items: { type: "string" }, description: "Optional: the trees being collected from, used for the out-of-band check. Defaults to the paths themselves." },
        max_bytes: { type: "integer", description: "Per-file ceiling; defaults to 64 MiB. A file above it is refused and recorded with its size." },
        scope: { type: "array", items: { type: "string" }, description: "Optional: the roots you claim as your own. A path outside it is refused rather than copied." },
        vault: { type: "string", description: "Optional: append one record of this run to a tamper-evident chain at this path, sealed when AIKAWAMEI_VAULT_PASSPHRASE is set." },
      },
      required: ["destination"],
    },
    async execute(args = {}) {
      const destination = typeof args.destination === "string" ? args.destination : "";
      if (!destination) {
        return {
          schema: COLLECT_SCHEMA, tool_version: VERSION,
          error: "A destination is required: this tool writes copies, and it will not choose where.",
          boundary_notice: NOTICE_WRITES, operations: OPS_WRITES,
        };
      }
      const wanted = (Array.isArray(args.paths) ? args.paths : []).filter((p) => typeof p === "string" && p);

      // The same scope guard as everywhere else, applied before a byte is read or written.
      const scope = Array.isArray(args.scope) && args.scope.length ? declaredScope(args.scope) : defaultScope();
      const { allowed, refused: refusedByScope } = classifyTargets(wanted, scope);

      const sources = Array.isArray(args.sources) && args.sources.length ? args.sources : wanted;
      // The out-of-band check is made against the trees the CALLER named, not only against what
      // survived the scope: a path refused by the scope must not thereby stop protecting the
      // destination from being inside the tree it came from.
      const inside = destinationInsideSources(destination, sources);

      // And then ACT on it. The first version computed this, reported it, and went ahead and copied
      // anyway -- because the module's own check only ever saw the individual files and never the tree
      // they came from. Reporting a refusal while doing the thing refused is worse than either.
      const run = inside
        ? { entries: [], manifest: [], refused: [], files_dir: null, manifest_path: null, manifest_head: null, order: [] }
        : collectInto({
            sources: allowed,
            destination,
            ...(Number.isInteger(args.max_bytes) ? { maxBytes: args.max_bytes } : {}),
          });

      const vaultPath = typeof args.vault === "string" && args.vault ? args.vault : null;
      const passphrase = process.env.AIKAWAMEI_VAULT_PASSPHRASE ?? null;
      let vault = null;
      if (vaultPath) {
        const note = `${run.entries.length} file(s) copied, ${run.refused.length + refusedByScope.length} refused`;
        const sealed = passphrase
          ? sealValue(passphrase, {
              destination: path.resolve(destination),
              scope: { mode: scope.mode, source: scope.source },
              refused: [...refusedByScope, ...run.refused],
              manifest: run.manifest.map((e) => ({ ordinal: e.ordinal, source: e.source, sha256: e.sha256, volatility: e.volatility })),
            })
          : null;
        try {
          const appended = appendRecord(vaultPath, { kind: "collection", note, sealed });
          vault = { path: vaultPath, length: appended.length, hash: appended.hash, sealed: sealed !== null };
        } catch (e) {
          vault = { path: vaultPath, error: String((e && e.message) || e) };
        }
      }

      return {
        schema: COLLECT_SCHEMA,
        tool_version: VERSION,
        destination: path.resolve(destination),
        files_dir: run.files_dir ?? null,
        manifest_path: run.manifest_path ?? null,
        manifest_head: run.manifest_head ?? null,
        order: run.order,
        scope: scopeReport(scope),
        refused_by_scope: refusedByScope,
        refused: run.refused,
        refused_destination: inside ? { destination: path.resolve(destination), inside } : null,
        entries: run.entries,
        collected: run.entries.length,
        by_volatility: tallyOf(run.entries.map((e) => ({ severity: e.volatility }))),
        not_reachable: COLLECT_NOT_REACHABLE,
        ...(vaultPath ? { vault } : {}),
        boundary_notice: NOTICE_WRITES, operations: OPS_WRITES,
      };
    },
  },

  {
    name: "aikawamei_self",
    operations: OPS_WRITES,
    description:
      "Compare THIS installation against a manifest you kept, and name every file added, removed or altered. It detects a change " +
      "and reports it; it PREVENTS NOTHING, and that is deliberate -- on a machine whose owner can become root, an agent that " +
      "survives its owner is one the owner can no longer account for. It can also verify a record chain against the length and head " +
      "a receipt reported, which is the only thing that catches a tail that was cut. The question it cannot answer is stated in the " +
      "response: an installation that has been removed cannot run, and so cannot report that it is gone.",
    inputSchema: {
      type: "object",
      properties: {
        root: { type: "string", description: "The installation root. Defaults to the directory this tool is installed in." },
        baseline: { type: "string", description: "Optional: a manifest written by an earlier run, to compare against." },
        out: { type: "string", description: "Optional: write the manifest of the present state here, to keep for the next run. Nothing is written unless this is given." },
        chain: { type: "string", description: "Optional: a record chain to verify, such as one aikawamei_sessions or aikawamei_collect left." },
        expect_length: { type: "integer", description: "Optional: the chain length a previous verification reported." },
        expect_head: { type: "string", description: "Optional: the chain head a previous verification reported." },
        vault: { type: "string", description: "Optional: append one record of this run to a tamper-evident chain at this path, sealed when AIKAWAMEI_VAULT_PASSPHRASE is set." },
      },
    },
    async execute(args = {}) {
      // `import.meta` is replaced by an empty object when this is bundled for the single-file
      // executable, so the directory is resolved behind a guard and the fallback is the working
      // directory. That defect is recorded in this project once already: reading `import.meta.url`
      // unguarded made both bundles fail to load while every artifact still built.
      const moduleDir = (() => {
        try {
          return typeof import.meta !== "undefined" && import.meta && import.meta.url ? path.dirname(fileURLToPath(import.meta.url)) : null;
        } catch { return null; }
      })();
      const installRoot = typeof args.root === "string" && args.root
        ? args.root
        : (moduleDir ? path.resolve(moduleDir, "..") : process.cwd());

      const scope = defaultScope();
      const { allowed } = classifyTargets([installRoot], scope);
      const root = allowed.length ? installRoot : null;

      const present = root
        ? manifestOf(root)
        : { schema: SELFCHECK_SCHEMA, root: installRoot, at: new Date().toISOString(), count: 0, entries: [] };
      const kept = typeof args.baseline === "string" && args.baseline ? readManifest(args.baseline) : null;
      const diff = kept ? compareManifests(kept, present) : null;

      let written = null;
      const outPath = typeof args.out === "string" && args.out ? args.out : null;
      if (outPath) {
        try {
          fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
          fs.writeFileSync(outPath, JSON.stringify(present, null, 2) + "\n", "utf8");
          written = outPath;
        } catch (e) {
          written = { path: outPath, error: String((e && e.message) || e) };
        }
      }

      let chain = null;
      if (typeof args.chain === "string" && args.chain) {
        const expectations = {};
        if (Number.isInteger(args.expect_length)) expectations.expectLength = args.expect_length;
        if (typeof args.expect_head === "string" && args.expect_head) expectations.expectHead = args.expect_head;
        try {
          const v = verifyFile(args.chain, expectations);
          chain = { path: args.chain, ...v, receipt: { length: v.length, head: v.head } };
        } catch (e) {
          chain = { path: args.chain, error: String((e && e.message) || e) };
        }
      }

      const vaultPath = typeof args.vault === "string" && args.vault ? args.vault : null;
      const passphrase = process.env.AIKAWAMEI_VAULT_PASSPHRASE ?? null;
      let vault = null;
      if (vaultPath) {
        const note = diff
          ? `${diff.added.length} added, ${diff.removed.length} removed, ${diff.changed.length} changed`
          : `${present.count} file(s) recorded, nothing to compare against`;
        const sealed = passphrase
          ? sealValue(passphrase, {
              root: present.root,
              diff,
              chain: chain && !chain.error ? { path: chain.path, length: chain.length, head: chain.head, ok: chain.ok } : null,
            })
          : null;
        try {
          const appended = appendRecord(vaultPath, { kind: "self-check", note, sealed });
          vault = { path: vaultPath, length: appended.length, hash: appended.hash, sealed: sealed !== null };
        } catch (e) {
          vault = { path: vaultPath, error: String((e && e.message) || e) };
        }
      }

      return {
        schema: SELFCHECK_SCHEMA,
        tool_version: VERSION,
        root: present.root,
        scope: scopeReport(scope),
        manifest_count: present.count,
        manifest: present,
        baseline: kept ? { path: args.baseline, count: kept.count } : null,
        diff,
        written,
        chain,
        not_possible: SELF_NOT_POSSIBLE,
        boundary_note: selfBoundary(),
        ...(vaultPath ? { vault } : {}),
        boundary_notice: NOTICE_WRITES, operations: OPS_WRITES,
      };
    },
  },
];

export { TOOLS };
export default { TOOLS, VERSION };