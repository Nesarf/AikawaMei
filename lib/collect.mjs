/**
 * AikawaMei - collection
 *
 * THE ONE THING IN THIS PROJECT THAT WRITES
 * -----------------------------------------
 * Every other tool here is read-only, and the boundary notices say so. A collector cannot be: its
 * whole job is to put a copy somewhere else before the original is gone. That is why the operation
 * vocabulary grew a fourth class for it rather than reusing one that would have made the notice
 * false in its first line.
 *
 * What the caller gets in exchange for the write is a claim it can check: every file is hashed as it
 * is copied, the manifest is a CHAIN so an entry cannot be altered or removed afterwards, and the
 * destination is refused if it sits inside what is being collected -- a copy kept inside the evidence
 * is not a copy.
 *
 * THE ORDER IS THE POINT, AND IT IS NOT MINE
 * ------------------------------------------
 * Collection runs most-perishable-first, because the things that are about to be overwritten or
 * pruned are the things nobody can collect later. RFC 3227 states the order as registers and cache,
 * then memory, then network state, then running processes, then disk -- and a read-only tool that
 * runs nothing reaches exactly ONE of those. So the order below is that list restricted to what this
 * tool can actually touch, and the surfaces it cannot touch are named with the instrument that can
 * (`winpmem`, `Get-NetTCPConnection`) rather than quietly left out of the ordering story.
 *
 * WHY NOTHING HERE IS COPIED FROM MEMORY OR FROM THE NETWORK STACK: reaching either means loading a
 * driver or running a program. Both are outside what this tool is, and a collector that quietly
 * started a helper would be a different kind of software than the one whose notice the operator read.
 */
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { lineHash } from "./vault.mjs";

export const COLLECT_SCHEMA = "aikawamei-collect/1";

/** Per-file ceiling. A file above it is REFUSED and recorded, never silently skipped. */
export const COLLECT_MAX_BYTES = 64 * 1024 * 1024;

/** Most perishable first. The keys are the order of volatility, restricted to what this can reach. */
export const VOLATILITY_ORDER = ["ephemeral", "rolling", "durable", "static"];

export const VOLATILITY_LABELS = {
  ephemeral: "about to be pruned or overwritten",
  rolling: "rolls over with use",
  durable: "persists until something changes it",
  static: "changes only when replaced",
};

/**
 * Which order of volatility this path belongs to.
 *
 * THE RULES RUN SPECIFIC-FIRST, NOT MOST-VOLATILE-FIRST, and that ordering is the whole of the
 * subtlety here. A generic "this is under a temp directory, so it is perishable" rule placed first
 * swallows every other answer: a Prefetch file, a task definition and an executable all live under
 * whatever path someone is collecting from, and on a machine where that path is itself temporary
 * they would every one of them be classified ephemeral. The name of a `.pf` file says what it is
 * regardless of where the copy sits.
 *
 * The cost of that choice, stated rather than hidden: a Prefetch file deliberately copied into a
 * temp directory is still classified as rolling, because a path is all this has. The classification
 * is a heuristic about what is likely to be lost first, not a fact about the file.
 *
 * A path that matches nothing is `durable`, the middle of the order and the honest answer for "I
 * cannot tell how soon this goes away".
 */
export function volatilityOf(p) {
  const s = String(p ?? "").replace(/\\/g, "/").toLowerCase();
  if (/\/prefetch\//.test(s) || /\.pf$/.test(s)) return "rolling";
  if (/\/(start menu|tasks|run|services)\//.test(s)) return "durable";
  if (/\.(exe|dll|sys|scr|com)$/.test(s)) return "static";
  if (/\/(wer|reportqueue|reportarchive|crashes|dumps)\//.test(s) || /\.(dmp|tmp|log)$/.test(s)) return "ephemeral";
  if (/\/(temp|tmp)\//.test(s)) return "ephemeral";
  if (/\.(xml|ini|conf|config|json|lnk)$/.test(s)) return "durable";
  return "durable";
}

/** Stable sort by volatility, keeping the caller's order inside a class. */
export function orderByVolatility(items) {
  const rank = (p) => VOLATILITY_ORDER.indexOf(volatilityOf(p));
  return (Array.isArray(items) ? items.slice() : [])
    .map((p, i) => ({ p, i }))
    .sort((a, b) => (rank(a.p) - rank(b.p)) || (a.i - b.i))
    .map((x) => x.p);
}

/** Is `destination` inside one of the sources? A copy kept inside the evidence is not a copy. */
export function destinationInsideSources(destination, sources) {
  const d = path.resolve(String(destination));
  const sep = path.sep;
  for (const s of Array.isArray(sources) ? sources : []) {
    const src = path.resolve(String(s));
    const root = src.endsWith(sep) ? src : src + sep;
    if (d === src || d.startsWith(root)) return src;
  }
  return null;
}

/** SHA-256 of a file, read in one pass. Returns null when it cannot be read. */
export function digestOfFile(file) {
  try {
    return createHash("sha256").update(fs.readFileSync(file)).digest("hex");
  } catch {
    return null;
  }
}

/**
 * Collect a list of files into a destination directory.
 *
 * Returns every decision it made, including the ones that went against it, so the caller can hand a
 * reader a record rather than a reassurance.
 */
export function collectInto({
  sources = [],
  destination,
  at = new Date().toISOString(),
  operator = null,
  maxBytes = COLLECT_MAX_BYTES,
  order = true,
} = {}) {
  const dest = destination ? path.resolve(destination) : null;
  const refused = [];
  const entries = [];
  if (!dest) {
    return { schema: COLLECT_SCHEMA, destination: null, entries, refused: [{ target: null, reason: "no destination was given" }], manifest: [] };
  }
  const inside = destinationInsideSources(dest, sources);
  if (inside) {
    return {
      schema: COLLECT_SCHEMA, destination: dest, entries, manifest: [],
      refused: [{ target: dest, reason: `the destination is inside ${inside}, which is being collected: a copy kept inside the evidence is not a copy` }],
    };
  }

  const ordered = order ? orderByVolatility(sources) : (Array.isArray(sources) ? sources.slice() : []);
  const filesDir = path.join(dest, "files");
  fs.mkdirSync(filesDir, { recursive: true });

  const manifest = [];
  let ordinal = 0;
  for (const src of ordered) {
    const source = path.resolve(String(src));
    let st = null;
    try { st = fs.statSync(source); } catch { st = null; }
    if (!st || !st.isFile()) {
      refused.push({ target: source, reason: st ? "not a regular file" : "not present or not readable" });
      continue;
    }
    if (st.size > maxBytes) {
      refused.push({ target: source, reason: `larger than the ceiling of ${maxBytes} bytes`, size: st.size });
      continue;
    }
    ordinal += 1;
    const copy = path.join(filesDir, `${String(ordinal).padStart(4, "0")}-${path.basename(source)}`);
    let copied = false;
    try {
      fs.copyFileSync(source, copy);
      // The copy carries the original's timestamps, because a copy whose mtime is when it was made
      // cannot be lined up against anything else in the case.
      fs.utimesSync(copy, st.atime, st.mtime);
      copied = true;
    } catch (e) {
      refused.push({ target: source, reason: `could not be copied: ${(e && e.message) || e}` });
      continue;
    }
    const digest = digestOfFile(copy);
    const entry = {
      ordinal,
      source,
      copy,
      volatility: volatilityOf(source),
      size: st.size,
      mtime: st.mtime.toISOString(),
      sha256: digest,
      collected_at: at,
      operator,
      verified: digest === digestOfFile(source),
      prev: manifest.length ? lineHash(JSON.stringify(manifest[manifest.length - 1])) : null,
    };
    manifest.push(entry);
    entries.push(entry);
    if (!copied) refused.push({ target: source, reason: "the copy was not written" });
  }

  const manifestPath = path.join(dest, "manifest.jsonl");
  fs.writeFileSync(manifestPath, manifest.map((e) => JSON.stringify(e)).join("\n") + (manifest.length ? "\n" : ""), "utf8");

  return {
    schema: COLLECT_SCHEMA,
    destination: dest,
    files_dir: filesDir,
    manifest_path: manifestPath,
    entries,
    manifest,
    refused,
    order: VOLATILITY_ORDER,
    manifest_head: manifest.length ? lineHash(JSON.stringify(manifest[manifest.length - 1])) : null,
  };
}

/**
 * What a collector of this shape cannot reach, with the instrument that can.
 *
 * Listed for the same reason the triage tool lists the registry surfaces: the order of volatility
 * begins with things this tool has no way to read, and an operator who does not know that would take
 * a complete run for a complete collection.
 */
export const COLLECT_NOT_REACHABLE = [
  {
    surface: "memory",
    why: "reading physical memory needs a signed driver loaded into the running kernel, and this tool loads nothing",
    answerable_by: "winpmem / DumpIt, or the OS's own crash-dump mechanism, then analyse the image elsewhere",
  },
  {
    surface: "live network state",
    why: "there is no file that holds the current connection table",
    answerable_by: "Get-NetTCPConnection -State Established   or   netstat -ano   or   ss -tanp",
  },
  {
    surface: "the process table",
    why: "same: it exists in the kernel, not on disk",
    answerable_by: "Get-Process | Select-Object Id,ProcessName,Path,StartTime",
  },
  {
    surface: "open file handles and loaded modules",
    why: "kernel state, and enumerating it needs a driver or a helper program",
    answerable_by: "handle.exe / listdlls.exe (Sysinternals), or /proc on Linux",
  },
];
