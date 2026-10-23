/**
 * AikawaMei - check catalog
 *
 * The audit's check surface, declared as DATA rather than buried in the audit functions.
 *
 * WHY THIS EXISTS (and what it deliberately is not)
 * -------------------------------------------------
 * The idea is borrowed from signature-rule engines: the set of checks a tool performs should
 * be a reviewable, versionable artifact rather than something you can only learn by reading
 * control flow. What is borrowed is the IDEA. There is no rule language, no expression
 * evaluator, and no `eval`: a prose-and-policy table cannot be turned into an injection
 * surface the way a pattern language can, and the probes this tool needs are semantic
 * (parse a torrc, read a pref, classify a volume), not textual pattern matches.
 *
 * So each entry declares WHAT a check reads, HOW BAD it is allowed to report, and WHAT IT
 * DOES NOT COVER -- and names how it is produced:
 *
 *   kind: "bespoke"    a hand-written evaluator in lib/core.mjs or lib/firefox.mjs names this
 *                      id. The catalog constrains it but does not generate it.
 *   kind: "builtin"    the catalog fully determines the check: it names one of BUILTIN_PROBES,
 *                      and evaluateBuiltins() runs it. Adding another check of a shape that
 *                      already exists is therefore a data change and nothing else.
 *
 * `severities` is a CONTRACT, not an observation: it is the set of severities this check is
 * allowed to emit. An audit that emits something outside its set is reported as a
 * conformance violation rather than silently accepted, which is what makes the table
 * enforced rather than decorative.
 *
 * Every entry carries `does_not_cover`. The project's standing rule is that a boundary claim
 * which is false in its first line is worse than no claim at all, so each check states its
 * own limit rather than leaving it to the shared boundary notice.
 */

import { createHash } from "node:crypto";
import path from "node:path";
import { daysSince, fmtBytes, fmtTime } from "./shared.mjs";

export const CHECKS_SCHEMA = "aikawamei-checks/1";

/** Bumped when the catalog's wording changes; the structural digest is what baselines compare. */
export const CATALOG_VERSION = "1";

// The targets a check may belong to. Closed on purpose: a new target is a claim about a NEW surface,
// and adding one is a decision that belongs in this line rather than in whichever module first wanted
// it. `content` joined for the content-rule item -- the one target whose checks read file BYTES rather
// than names, which is why its entries carry a matcher and a pattern where the others carry a probe
// name. `attribution` joined for the takedown item, and it is the only target whose findings are about
// something OUTSIDE this machine: the records a registry holds about a name or a number.
export const TARGETS = ["tor", "firefox", "handoff", "sessions", "triage", "content", "attribution"];

/**
 * What a check DOES, as a closed set -- the vocabulary behind "the boundary is stated per
 * operation" rather than in one sentence with an exception bolted on.
 *
 * The set exists because a single global claim cannot be true of every tool. "Never touches the
 * network (except the version lookup)" is a correct sentence for the one tool that performs a lookup
 * and an OVER-PERMISSIVE one for the tools that do not: it leaves a reader unable to tell a tool that
 * might reach out from one that cannot. Each check and each tool declares which of these it performs,
 * and the notice a caller receives is derived from the declaration.
 *
 * EACH CLASS CONTRIBUTES A CLAUSE, AND THE NOTICE JOINS THEM -- it is not chosen from a ranking.
 * A ranking was the first attempt and it is wrong the moment two classes are incomparable, which
 * `writes` and `lookup` are: a tool that both writes a copy and asks an endpoint, described by
 * whichever class ranked higher, would be described truthfully and INCOMPLETELY, and a boundary
 * claim that is true by omission is the one thing this project treats as worse than no claim.
 *
 * `active` is declared and currently unused -- deliberately. The rule has to be in place before the
 * first check that needs it, or the first dynamic check gets written first and the boundary is
 * described afterwards.
 */
export const OPERATIONS = {
  static: {
    key: "static",
    label: "Reads files",
    clause: "reads files and never launches the application under audit",
  },
  writes: {
    key: "writes",
    label: "Writes a copy",
    clause: "writes files at paths you name when you ask it to, and never modifies or moves what it reads",
  },
  // A FOURTH CLASS, and the reason `writes` could not cover it: that clause ends "never modifies or
  // moves what it reads", which deletion does by definition. Folding removal in there would have made
  // an existing sentence false for every tool that carries it -- the same failure the class list was
  // built to prevent. So it is a class of its own, and the notice for a removing tool says both
  // things: it reads, and it removes what an earlier read reported.
  removes: {
    key: "removes",
    label: "Removes reported files",
    clause: "removes files that an earlier audit of this tool reported, and never anything else",
  },
  // A FIFTH CLASS, and the only one that changes the running state of the machine. It is separate
  // from `removes` because ending a process is not deleting a file: the file survives, and on a
  // program that can restart itself the process is back before the report is read. The clause says
  // both halves -- what it ends, and that it starts nothing.
  terminates: {
    key: "terminates",
    label: "Ends processes",
    clause: "ends processes it was pointed at, and starts none",
  },
  lookup: {
    key: "lookup",
    label: "Version lookup",
    clause: "looks up the current version at one public endpoint",
  },
  active: {
    key: "active",
    label: "Sends traffic to a target",
    clause: "sends traffic to a target, so it is not read-only",
  },
};

/** The order clauses appear in a notice. Fixed, so the same declaration always reads the same way. */
export const OPERATION_ORDER = ["static", "writes", "removes", "terminates", "lookup", "active"];

/** The network sentence, which depends on which of `lookup` and `active` are declared. */
export function networkClause(operations) {
  const declared = new Set((Array.isArray(operations) ? operations : []).filter((o) => Object.prototype.hasOwnProperty.call(OPERATIONS, o)));
  if (declared.has("active")) return null; // the `active` clause already says it
  if (declared.has("lookup")) return "and touches the network only for that lookup";
  return "and never touches the network";
}


/** Probes the catalog can name and evaluateBuiltins() knows how to run. */
export const BUILTIN_PROBES = {
  VOLUME_ENCRYPTION: "volume-encryption",
  PATH_RESIDUE: "path-residue",
  PATH_LIST: "path-list",
  DIR_ENTRIES: "dir-entries",
  DIR_SIZE: "dir-size",
  JSON_FIELD: "json-field",
  CONFIG_VALUE: "config-value",
  STATIC: "static",
  TREE_MATCH: "tree-match",
};

/**
 * The value predicates a `config-value` variant may match on.
 *
 * Deliberately a closed set of eight, each taking a key name and at most one literal argument,
 * with FIRST MATCH winning and no composition or nesting. That boundary is the whole design: a
 * predicate vocabulary that can be combined is a programming language, and a programming language
 * living in a data file has worse error messages and worse tooling than the JavaScript it replaced.
 * When a check needs two predicates combined, it is code-shaped and stays code.
 */
export const VALUE_PREDICATES = ["absent", "present", "truthy", "is_true", "is_false", "one_of", "any_true", "all_false", "any_present"];

/* =====================================================================
 * The catalog
 *
 * Fields:
 *   id            stable identifier; findings carry it and baselines key on it
 *   layer         build | transport | crypto | metadata | endpoint
 *   targets       which target produces this check
 *   kind          "bespoke" | "builtin"
 *   severities    allowed severity set (the contract)
 *   observes      the static input it reads (one line)
 *   does_not_cover  its own boundary (one line)
 *   fact          optional dotted path: where its evidence lands in the facts record
 *   probe         builtin only: which BUILTIN_PROBES entry it runs
 *   probe_args    builtin only: the probe's own arguments (base, file, evidence shape, ...)
 *   title         builtin only: the finding title, as a template
 *   detail        builtin only: the finding detail, as a template
 *   detail_if_stale  builtin only: used instead of `detail` when the probe reports staleness
 *
 * Templates substitute `{name}`-style placeholders from a fixed set the probe provides
 * (name, size, age, count, path, mtime). An unknown placeholder is left visible rather than
 * blanked, so a typo shows up in the output instead of producing a silently empty sentence --
 * and the suite asserts that no entry leaves a placeholder unresolved.
 *
 * The prose for a built-in check lives HERE, not in the evaluator. That is the whole point of
 * the distinction: a built-in check's behaviour, wording and severity are all reviewable in one
 * table, and adding another check of a shape that already exists is a data change and nothing
 * else.
 * ===================================================================== */

export const CHECK_CATALOG = [
  /* ---------------------------------------------------------------- Tor: build */
  {
    id: "tb-version", layer: "build", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok", "warn"],
    observes: "Browser/tbb_version.json and Browser/application.ini",
    does_not_cover: "Whether the installed build is authentic: a modified install can carry an unmodified version file.",
    fact: "build.tor_browser_version",
  },
  {
    id: "tor-version", layer: "build", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["info"],
    observes: "the TorVersion line in the Data/Tor/state file",
    does_not_cover: "Whether tor.exe matches the version the state file claims; nothing here hashes a binary.",
    fact: "build.tor_version",
  },
  /* ---------------------------------------------------------------- Tor: transport */
  {
    id: "bridges", layer: "transport", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok", "warn", "info"],
    observes: "UseBridges and Bridge lines across torrc-defaults merged with torrc",
    does_not_cover: "Whether any bridge is reachable: this tool never connects to one.",
    fact: "transport.bridges",
  },
  {
    id: "bridge-blend", layer: "transport", targets: ["tor"], kind: "builtin", operation: "static", severities: ["ok"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs",
      keys: { builtin_type: "torbrowser.settings.bridges.builtin_type", source: "torbrowser.settings.bridges.source" },
      variants: [{ key: "builtin_type", truthy: true, severity: "ok" }],
      evidence: { builtin_type: "{builtin_type}", source: "{source}" },
    },
    title: "Using built-in bridges ({builtin_type})",
    detail: "Built-in bridges are byte-identical to everyone else who picked the same option - which is exactly the point: your configuration lines are not a distinguishing feature. A custom bridge would stand out of the crowd.",
    observes: "torbrowser.settings.bridges.builtin_type and .source in prefs.js",
    does_not_cover: "Whether the built-in set is still distributed to new clients; that changes upstream, not here.",
    fact: "transport.bridge_builtin_type",
  },
  {
    id: "utls", layer: "transport", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok"],
    observes: "utls-imitate= parameters on Bridge lines",
    does_not_cover: "Whether the impersonated fingerprint still matches the current real browser.",
    fact: "transport.utls",
  },
  {
    id: "fronting", layer: "transport", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok"],
    observes: "fronts= parameters on Bridge lines",
    does_not_cover: "Whether the fronting domain still permits it; CDN policy can withdraw that at any time.",
    fact: "transport.fronts",
  },
  {
    id: "pt-list", layer: "transport", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["info"],
    observes: "ClientTransportPlugin lines",
    does_not_cover: "Which of the loaded transports is actually in use; loaded is not enabled.",
    fact: "transport.plugins",
  },
  {
    id: "deprecated-pt", layer: "transport", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["warn"],
    observes: "the set of bridge types in use against the known-obsolete list",
    does_not_cover: "Whether a non-obsolete type is genuinely effective today; that is a research question, not a config fact.",
    fact: "transport.deprecated_pt",
  },
  {
    id: "quickstart", layer: "transport", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs", keys: { quickstart: "torbrowser.settings.quickstart.enabled" },
      // One variant and no fallback: the check fires only when the pref is exactly true, which is
      // the `=== true` the code used. A variant set with no `always` is how "only under this
      // condition" is expressed, with no separate guard field.
      variants: [{ key: "quickstart", is_true: true, severity: "info" }],
      evidence: { quickstart: true },
    },
    title: "Quickstart enabled (connects on launch)",
    detail: "Convenient, but it anchors connection times to your usage habits, which over time forms a predictable temporal pattern. Manual connection is more controllable if timing matters to you.",
    observes: "torbrowser.settings.quickstart.enabled in prefs.js",
    does_not_cover: "Whether connect-on-launch actually correlates with anything: this reports the setting, not a traffic pattern.",
    fact: "transport.quickstart",
  },
  /* ---------------------------------------------------------------- Tor: crypto */
  {
    id: "onion-auth-configured", layer: "crypto", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok"],
    observes: "ClientOnionAuthDir and the *.auth_private files inside it",
    does_not_cover: "Whether the corresponding service still exists or still trusts these keys.",
    fact: "crypto.client_auth_dir",
  },
  {
    id: "onion-auth-empty", layer: "crypto", targets: ["tor", "handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    // max_count 0 is how "configured but unused" is expressed. The probe is gated by the base
    // directory existing, so an unconfigured ClientOnionAuthDir produces no finding at all --
    // which is exactly the precondition the code this replaced checked by hand.
    probe_args: { base: "auth_dir", pattern: "\\.auth_private$", min_count: 0, max_count: 0, evidence: "dir-only" },
    title: "Client authorization directory is empty (ready but unused)",
    detail: "Not an error - it just means no contact/service keys have been added yet. Drop *.auth_private files in when you need it.",
    observes: "the count of *.auth_private files in ClientOnionAuthDir",
    does_not_cover: "Why the directory is empty; an unused mechanism and a broken one look identical here.",
    fact: "crypto.client_auth_keys",
  },
  {
    id: "onion-auth-keys", layer: "crypto", targets: ["tor", "handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    probe_args: { base: "auth_dir", pattern: "\\.auth_private$", min_count: 1 },
    title: "{count} client authorization key(s) present",
    detail: "These keys are themselves sensitive assets: whoever holds one can reach the corresponding service.",
    observes: "the names of the *.auth_private files present",
    does_not_cover: "Whether these keys are still needed; unused key material is still key material.",
    fact: "crypto.client_auth_key_names",
  },
  {
    id: "onion-auth-absent", layer: "crypto", targets: ["tor", "handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "base", keys: { auth_dir: "auth_dir" },
      require_base: "data_dir",
      variants: [{ key: "auth_dir", absent: true, severity: "info" }],
      evidence: null,
    },
    title: "Onion service client authorization not configured",
    detail: "If you need a drop point that only specific people can reach, this is the simplest and most robust mechanism.",
    observes: "the absence of ClientOnionAuthDir from the effective configuration",
    does_not_cover: "Whether the caller needs conditional reachability at all.",
  },
  {
    id: "hs-keys", layer: "crypto", targets: ["tor"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    probe_args: { base: "keys_dir", evidence: "entries", max_names: 10 },
    title: "Onion service private key directory present ({count} entries)",
    detail: "If this machine hosts a .onion service, taking these keys means complete takeover of the service. Confirm you really need to host it persistently here.",
    observes: "the Data/Tor/keys directory",
    does_not_cover: "Whether the hosted service is still published, or whether these keys are still valid.",
    fact: "crypto.hs_keys",
  },
  /* ---------------------------------------------------------------- Tor: metadata */
  {
    id: "state-file", layer: "metadata", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["warn"],
    observes: "size and LastWritten of Data/Tor/state",
    does_not_cover: "What the guard and bridge records actually refer to; the audit deliberately does not resolve them.",
    fact: "metadata.state",
  },
  {
    id: "state-no-guards", layer: "metadata", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["info", "warn"],
    observes: "the guard and CircuitBuildTimeBin line counts in the state file",
    does_not_cover: "Whether circuits ever built successfully; absence of guard records is not proof of absence of use.",
    fact: "metadata.state_guard_absence",
  },
  {
    id: "state-guards", layer: "metadata", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["warn"],
    observes: "Guard in= / EntryGuard lines and their guard sets in the state file",
    does_not_cover: "Whether those guards were ever actually used for traffic.",
    fact: "metadata.state_guards",
  },
  {
    id: "cache-cached-descriptors", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-descriptors", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-descriptors",
    does_not_cover: "Whether the cached relays were ever contacted; a cache proves contact with the directory authorities, not with a peer.",
    fact: "metadata.caches.descriptors",
  },
  {
    id: "cache-cached-microdescs", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-microdescs", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-microdescs",
    does_not_cover: "Same limit as the other descriptor caches: contact with authorities, not with peers.",
    fact: "metadata.caches.microdescs",
  },
  {
    id: "cache-cached-microdescs.new", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-microdescs.new", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-microdescs.new",
    does_not_cover: "Same limit as the other descriptor caches: contact with authorities, not with peers.",
    fact: "metadata.caches.microdescs_new",
  },
  {
    id: "cache-cached-certs", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-certs", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-certs",
    does_not_cover: "Nothing here is identifying on its own; it dates directory-authority contact only.",
    fact: "metadata.caches.certs",
  },
  {
    id: "cache-cached-consensus", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "data_dir", file: "cached-consensus", min_size: 1, stale_days: 90 },
    title: "Descriptor cache {name}: {size} (updated {age} day(s) ago)",
    detail: "Updated recently, so it has genuinely been in use. It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    detail_if_stale: "Not updated for a long time - this install has been idle. Idle residue is still a forensic asset: It does not identify you directly, but combined with state and timestamps it outlines a usage pattern.",
    observes: "presence, size and age of Data/Tor/cached-consensus",
    does_not_cover: "A consensus snapshot is public data; its presence dates activity rather than revealing a destination.",
    fact: "metadata.caches.consensus",
  },
  {
    id: "pt-state", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    probe_args: { base: "data_dir", file: "pt_state", max_names: 10 },
    title: "pt_state retains {count} file(s)",
    detail: "State residue from pluggable transports (bridge/endpoint caches).",
    observes: "the file count under Data/Tor/pt_state",
    does_not_cover: "What the transport state contains; this reports residue, not its meaning.",
    fact: "metadata.pt_state",
  },
  {
    id: "profile-times", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.JSON_FIELD,
    // The probe reads two fields and prefers the first, which is the `firstUse ?? created` the
    // code did. There is no way to express a three-field fallback, and that is the point: the
    // moment a probe needs a chain of conditions it has become code.
    probe_args: { base: "profile_dir", file: "times.json", primary: "firstUse", fallback: "created" },
    title: "Browser profile records a first-use time ({time})",
    detail: "Not a privacy leak in itself, but it is hard evidence of when this machine started using Tor, and the overall outline of usage cannot be erased. If the existence of the activity itself must leave no trace, a persistent install cannot do it - that requires an amnesic environment.",
    observes: "firstUse / created in the browser profile's times.json",
    does_not_cover: "Whether the recorded time is the true first use; a copied profile carries the original timestamp.",
    fact: "metadata.profile_times",
  },
  {
    id: "session-checkpoints", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "sessionCheckpoints.json", min_size: 1 },
    title: "Session checkpoints present (sessionCheckpoints.json)",
    detail: "Window/tab restore state. If you used it for anything sensitive, this file may indirectly reflect what kinds of targets you visited.",
    observes: "presence and size of sessionCheckpoints.json in the profile",
    does_not_cover: "What the restored tabs were; the audit reads the file's existence, never its contents.",
    fact: "metadata.session_checkpoints",
  },
  {
    id: "places", layer: "metadata", targets: ["tor"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "places.sqlite", min_size: 1 },
    title: "Browsing history database present (places.sqlite, {size})",
    detail: "Tor Browser clears this on exit by default, so its presence means either it never exited cleanly or the cleanup did not take effect. Confirm by hand.",
    observes: "presence and size of places.sqlite in the profile",
    does_not_cover: "Whether the database still holds rows: an allocated but empty database looks the same as a populated one from the outside.",
    fact: "metadata.places",
  },
  /* ---------------------------------------------------------------- Tor: endpoint */
  {
    id: "disk-location", layer: "endpoint", targets: ["tor"], kind: "bespoke", operation: "static", severities: ["ok", "info"],
    observes: "the drive letter of the install root against SystemDrive",
    does_not_cover: "Whether that drive is encrypted or removable; see disk-encryption.",
    fact: "endpoint.disk_location",
  },
  {
    id: "no-stray-traces", layer: "endpoint", targets: ["tor"], kind: "builtin", operation: "static", severities: ["ok"],
    probe: BUILTIN_PROBES.PATH_LIST,
    probe_args: {
      mode: "none-present",
      exclude_equal_to: "install_root",
      paths: [
        "{home}/AppData/Roaming/Tor Browser", "{home}/AppData/Local/Tor Browser",
        "{home}/Desktop/Tor Browser", "{home}/Documents/Tor Browser",
        "{home}/Downloads/Tor Browser", "{tmp}/Tor Browser",
      ],
    },
    title: "No Tor residue in user or temp directories",
    detail: "Roaming/Local/Desktop/Documents/Downloads/temp are all clean; data lives only in the designated install.",
    observes: "six named locations under the user profile and the temp directory",
    does_not_cover: "Copies anywhere else on the machine: this is a fixed list, not a filesystem-wide search.",
  },
  {
    id: "stray-traces", layer: "endpoint", targets: ["tor"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.PATH_LIST,
    probe_args: {
      exclude_equal_to: "install_root",
      paths: [
        "{home}/AppData/Roaming/Tor Browser", "{home}/AppData/Local/Tor Browser",
        "{home}/Desktop/Tor Browser", "{home}/Documents/Tor Browser",
        "{home}/Downloads/Tor Browser", "{tmp}/Tor Browser",
      ],
    },
    title: "Found {count} stray Tor cop(y/ies) in user directories",
    detail: "Extra copies fragment your cleanup surface: you think you removed one, another remains.",
    observes: "six named locations under the user profile and the temp directory",
    does_not_cover: "Copies anywhere else on the machine: this is a fixed list, not a filesystem-wide search.",
    fact: "endpoint.stray_traces",
  },
  {
    id: "persistence", layer: "endpoint", targets: ["tor"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.STATIC,
    probe_args: { evidence: { root: "{root}" } },
    title: "This install is persistent (not amnesic)",
    detail: "Everything on disk survives across sessions: state, descriptor caches, the profile, and possibly downloads. Cryptography cannot help here at all - only environment isolation (an amnesic OS) or full-disk encryption manages it.",
    observes: "nothing on disk; it restates that this install design is persistent",
    does_not_cover: "Whether persistence is acceptable for the caller's threat model. Only an amnesic environment changes it.",
    fact: "endpoint.persistence",
  },
  {
    id: "disk-encryption", layer: "endpoint", targets: ["tor", "firefox"], kind: "builtin", operation: "static",
    severities: ["ok", "info", "warn"], probe: BUILTIN_PROBES.VOLUME_ENCRYPTION,
    observes: "the mount table (Linux) or the filesystem type reported for the volume root (other platforms)",
    does_not_cover:
      "On Windows a static audit cannot read BitLocker state at all without elevation, so undetermined is reported rather than a guess; " +
      "elsewhere a whole-disk container that has already been unlocked is indistinguishable from an unencrypted volume.",
    fact: "endpoint.volume_encryption",
  },

  /* ---------------------------------------------------------------- Firefox */
  {
    id: "ff-version", layer: "build", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["info", "warn"],
    observes: "application.ini of the installed Firefox, falling back to compatibility.ini in the profile",
    does_not_cover: "Whether that build is authentic or current; see aikawamei_version for freshness.",
    fact: "build.firefox_version",
  },
  {
    id: "ff-proxy", layer: "transport", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["info"],
    observes: "network.proxy.type and the manual proxy prefs",
    does_not_cover: "How traffic is actually routed; other applications on the machine are unaffected by a browser proxy.",
    fact: "transport.proxy_mode",
  },
  {
    id: "ff-doh", layer: "transport", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["ok", "info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs",
      keys: { trr_mode: "network.trr.mode", trr_uri: "network.trr.uri", trr_custom: "network.trr.custom_uri" },
      labels: { trr_mode: { 0: "off", 1: "race against system DNS", 2: "DoH first", 3: "DoH only", 5: "off by explicit choice" } },
      variants: [
        { key: "trr_mode", one_of: [2, 3], severity: "ok",
          title: "DNS over HTTPS: {trr_mode_label}",
          detail: "DoH is active, which keeps DNS queries away from the local resolver. Note that the DoH provider itself sees every lookup, so the provider matters." },
        { key: "trr_mode", present: true, severity: "info",
          title: "DNS over HTTPS: {trr_mode_label}",
          detail: "DoH is not active; DNS goes to the system resolver. On an untrusted network that is a visible channel." },
      ],
      evidence: { trr_mode: "{trr_mode}", trr_uri: "{trr_uri}", trr_custom: "{trr_custom}" },
    },
    title: "DNS over HTTPS",
    detail: "DNS over HTTPS",
    observes: "network.trr.mode",
    does_not_cover: "Whether the chosen DoH provider is trustworthy; it sees every lookup.",
    fact: "transport.doh_mode",
  },
  {
    id: "ff-content-blocking", layer: "transport", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["ok", "info"],
    observes: "browser.contentblocking.category and tracking protection prefs",
    does_not_cover: "What a given site actually serves; blocking is not isolation.",
    fact: "transport.content_blocking",
  },
  {
    id: "ff-rfp", layer: "transport", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["ok", "info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs", keys: { rfp: "privacy.resistFingerprinting" }, booleans: ["rfp"],
      variants: [
        { key: "rfp", is_true: true, severity: "ok",
          title: "Fingerprint resistance: enabled",
          detail: "privacy.resistFingerprinting is on. Note that it changes the profile's own fingerprint, so it is a deviation from the default population unless many others run the same configuration." },
        { key: "rfp", is_false: true, severity: "info",
          title: "Fingerprint resistance: disabled",
          detail: "Fingerprint resistance is off. A default Firefox is highly distinguishable by its own configuration, which undercuts any attempt to look unremarkable." },
      ],
      evidence: { resistFingerprinting: "{rfp}" },
    },
    title: "Fingerprint resistance",
    detail: "Fingerprint resistance",
    observes: "privacy.resistFingerprinting",
    does_not_cover: "Whether the resulting fingerprint blends in; enabling it is itself a deviation from the default population.",
    fact: "transport.resist_fingerprinting",
  },
  {
    id: "ff-cookie-behavior", layer: "transport", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["ok", "info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs", keys: { cookieBehavior: "network.cookie.cookieBehavior" },
      labels: { cookieBehavior: { 0: "accept all", 1: "block third-party", 2: "block all", 3: "block from unvisited", 4: "block cross-site trackers", 5: "total cookie protection" } },
      variants: [
        { key: "cookieBehavior", one_of: [4, 5], severity: "ok",
          title: "Cookie policy: {cookieBehavior_label}",
          detail: "Cross-site tracking cookies are partitioned or blocked." },
        { key: "cookieBehavior", present: true, severity: "info",
          title: "Cookie policy: {cookieBehavior_label}",
          detail: "Cookies from other sites are accepted, which is what makes cross-site tracking work in the first place." },
      ],
      evidence: { cookieBehavior: "{cookieBehavior}" },
    },
    title: "Cookie policy",
    detail: "Cookie policy",
    observes: "network.cookie.cookieBehavior",
    does_not_cover: "First-party tracking, which no cookie policy addresses.",
    fact: "transport.cookie_behavior",
  },
  {
    id: "ff-logins", layer: "crypto", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "logins.json", min_size: 1 },
    title: "Saved passwords database present ({size}, written {age} day(s) ago)",
    detail: "logins.json holds the encrypted entry set for saved logins, with key4.db beside it. This is the highest-value file in a Firefox profile: whoever obtains the profile directory and the primary password (or cracks a weak one) obtains every saved credential. If this profile was ever used for anything that matters, treat those credentials as disclosed unless a strong primary password is set.",
    observes: "presence, size and age of logins.json",
    does_not_cover: "Whether a primary password is set; prefs.js does not record that, so the file's strength is not determinable here.",
    fact: "crypto.saved_logins",
  },
  {
    id: "ff-keys", layer: "crypto", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "key4.db", min_size: 1 },
    title: "Firefox key material present ({size}, written {age} day(s) ago)",
    detail: "key4.db is the NSS key database that protects saved logins and client certificates.",
    observes: "presence, size and age of key4.db",
    does_not_cover: "The strength of the primary password protecting it.",
    fact: "crypto.key_db",
  },
  {
    id: "ff-certs", layer: "crypto", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "cert9.db", min_size: 1 },
    title: "Client certificate store present ({size}, written {age} day(s) ago)",
    detail: "cert9.db can hold client certificates used to authenticate to services. Their presence is itself an identifier of which services this profile talks to.",
    observes: "presence, size and age of cert9.db",
    does_not_cover: "Which services the certificates authenticate to; only their existence is read.",
    fact: "crypto.cert_db",
  },
  {
    id: "ff-primary-password", layer: "crypto", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["warn", "ok"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs", keys: { signon_rememberSignons: "signon.rememberSignons" }, booleans: ["signon_rememberSignons"],
      variants: [
        { key: "signon_rememberSignons", is_true: true, severity: "warn",
          title: "Password saving is enabled",
          detail: "Firefox will offer to store credentials. This audit cannot tell whether a primary password is set -- prefs.js does not record it -- so confirm from the profile itself if it matters. Without one, the stored logins are only as safe as the machine." },
        { key: "signon_rememberSignons", is_false: true, severity: "ok",
          title: "Password saving is disabled",
          detail: "Firefox will not store new credentials. Anything already in logins.json is unaffected by this setting." },
      ],
      evidence: { signon_rememberSignons: "{signon_rememberSignons}" },
    },
    title: "Password saving",
    detail: "Password saving",
    observes: "signon.rememberSignons",
    does_not_cover: "Whether a primary password is actually set: this preference does not record it.",
    fact: "crypto.password_saving",
  },
  {
    id: "ff-history", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "places.sqlite", min_size: 1 },
    title: "Browsing history and bookmarks database present ({size}, written {age} day(s) ago)",
    detail: "Firefox keeps history here by design, so its presence is expected rather than a misconfiguration. It still records what this profile has visited, and it is the first file examined if the machine is taken.",
    observes: "presence, size and age of places.sqlite",
    does_not_cover: "Which sites were visited; the audit reads file metadata, never the database contents.",
    fact: "metadata.history",
  },
  {
    id: "ff-cookies", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "cookies.sqlite", min_size: 1 },
    title: "Cookie database present ({size}, written {age} day(s) ago)",
    detail: "Persistent session cookies. For a signed-in profile these can be replayed to impersonate the session without the password.",
    observes: "presence, size and age of cookies.sqlite",
    does_not_cover: "Which sessions are live; a cookie database is replayable regardless of the sites' own expiry policy.",
    fact: "metadata.cookies",
  },
  {
    id: "ff-permissions", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "permissions.sqlite", min_size: 1 },
    title: "Per-site permission grants present ({size}, written {age} day(s) ago)",
    detail: "Records which sites were granted camera, microphone, geolocation, notifications and so on. The list reveals which services this profile actually uses.",
    observes: "presence, size and age of permissions.sqlite",
    does_not_cover: "Which grants are still meaningful; only the file's existence and size are read.",
    fact: "metadata.permissions",
  },
  {
    id: "ff-formhistory", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "formhistory.sqlite", min_size: 1 },
    title: "Form history present ({size}, written {age} day(s) ago)",
    detail: "Previously typed form values, including anything entered into a field that was not marked as a password field.",
    observes: "presence, size and age of formhistory.sqlite",
    does_not_cover: "What was typed; the audit does not read form values.",
    fact: "metadata.formhistory",
  },
  {
    id: "ff-favicons", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_RESIDUE,
    probe_args: { base: "profile_dir", file: "favicons.sqlite", min_size: 1 },
    title: "Favicon cache present ({size}, written {age} day(s) ago)",
    detail: "Small, but it survives history clearing and is a recognisable list of visited sites.",
    observes: "presence, size and age of favicons.sqlite",
    does_not_cover: "Which sites the icons belong to; the file is treated as residue only.",
    fact: "metadata.favicons",
  },
  {
    id: "ff-site-data", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_SIZE,
    probe_args: { base: "profile_dir", file: "storage/default", min_size: 1 },
    title: "Site storage present ({size})",
    detail: "IndexedDB, service worker caches and similar per-origin storage. It is not cleared by clearing history, and it can identify the sites this profile has used.",
    observes: "the total size of storage/default",
    does_not_cover: "Which origins own that storage; clearing history does not clear it, which is the point being made.",
    fact: "metadata.site_data",
  },
  {
    id: "ff-times", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.JSON_FIELD,
    probe_args: { base: "profile_dir", file: "times.json", primary: "firstUse", fallback: "created" },
    title: "Profile records a first-use time ({time})",
    detail: "Not an exposure by itself, but it dates the profile and cannot be removed without resetting the profile.",
    observes: "firstUse / created in times.json",
    does_not_cover: "Whether the timestamp is the true first use; a copied profile carries the original value.",
    fact: "metadata.firefox_profile_times",
  },
  {
    id: "ff-session", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.DIR_ENTRIES,
    probe_args: { base: "profile_dir", file: "sessionstore-backups", evidence: "session" },
    title: "{count} session restore file(s) present",
    detail: "Session backups contain the open tab set and, in some builds, form and scroll state. They survive a crash and are worth clearing before handing a machine over.",
    observes: "the count of sessionstore files and the newest mtime",
    does_not_cover: "What the restored tabs were; only the file set is read.",
    fact: "metadata.session_store",
  },
  {
    id: "ff-telemetry", layer: "metadata", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["warn", "info"],
    observes: "datareporting/state.json for a client ID",
    does_not_cover: "Whether that ID has ever been transmitted; the audit sees the local record only.",
    fact: "metadata.telemetry_client_id",
  },
  {
    id: "ff-sync", layer: "metadata", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["warn"],
    observes: "signedInUser.json, prefs.js sync username, and the account root",
    does_not_cover: "What the account is; the linkage is reported, the identity is not resolved.",
    fact: "metadata.sync_linked",
  },
  {
    id: "ff-extensions", layer: "metadata", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["info"],
    observes: "extensions.json for active extensions",
    does_not_cover: "What an extension does with its access; installing is trusting.",
    fact: "metadata.active_extensions",
  },
  {
    id: "ff-telemetry-prefs", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["ok", "info"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs",
      keys: { toolkit_telemetry_enabled: "toolkit.telemetry.enabled", healthreport_uploadEnabled: "datareporting.healthreport.uploadEnabled" },
      booleans: ["toolkit_telemetry_enabled", "healthreport_uploadEnabled"],
      variants: [
        { all_false: true, severity: "ok",
          title: "Telemetry upload disabled in prefs",
          detail: "Both toolkit.telemetry.enabled and datareporting.healthreport.uploadEnabled are false. The client ID may still exist on disk; see the telemetry finding above." },
        { any_present: true, severity: "info",
          title: "Telemetry prefs leave upload possible",
          detail: "At least one telemetry preference still allows reporting. Confirm the current defaults for your build, since Mozilla has changed how these prefs interact." },
      ],
      evidence: { toolkit_telemetry_enabled: "{toolkit_telemetry_enabled}", healthreport_uploadEnabled: "{healthreport_uploadEnabled}" },
    },
    title: "Telemetry preferences",
    detail: "Telemetry preferences",
    observes: "toolkit.telemetry.enabled and datareporting.healthreport.uploadEnabled",
    does_not_cover: "How these prefs interact in the caller's specific build; Mozilla has changed that more than once.",
    fact: "metadata.telemetry_upload_disabled",
  },
  {
    id: "ff-sponsored", layer: "metadata", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info", "ok"],
    probe: BUILTIN_PROBES.CONFIG_VALUE,
    probe_args: {
      source: "prefs",
      keys: { showSponsored: "browser.newtabpage.activity-stream.showSponsored", pocket: "extensions.pocket.enabled" },
      booleans: ["showSponsored", "pocket"],
      variants: [
        { any_true: true, severity: "info",
          title: "Sponsored content or Pocket is enabled",
          detail: "These features contact Mozilla-operated endpoints and are tied to the browser. They are not a leak of local residue, but they are remote relationships worth knowing about." },
        { any_present: true, severity: "ok",
          title: "Sponsored content and Pocket are disabled",
          detail: "No Mozilla content endpoints are enabled from this profile." },
      ],
      evidence: { showSponsored: "{showSponsored}", pocket: "{pocket}" },
    },
    title: "Sponsored content",
    detail: "Sponsored content",
    observes: "the sponsored-content and Pocket prefs",
    does_not_cover: "Whether any such content was ever shown or clicked.",
    fact: "metadata.sponsored_enabled",
  },
  {
    id: "ff-profile-location", layer: "endpoint", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["info"],
    observes: "the drive letter of the profile directory against SystemDrive",
    does_not_cover: "Whether that drive is encrypted or removable; see disk-encryption.",
    fact: "endpoint.firefox_profile_location",
  },
  {
    id: "ff-persistence", layer: "endpoint", targets: ["firefox"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.STATIC,
    probe_args: { evidence: { profile_dir: "{profile_dir}" } },
    title: "This profile is persistent",
    detail: "Everything on disk survives across sessions. Cryptography cannot help here: only full-disk encryption or an amnesic environment changes this.",
    observes: "nothing on disk; it restates that a profile directory is persistent",
    does_not_cover: "Whether persistence matters for the caller's threat model.",
    fact: "endpoint.firefox_persistence",
  },
  {
    id: "ff-profile-count", layer: "endpoint", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["warn"],
    observes: "the number of discovered Firefox profiles",
    does_not_cover: "Whether the other profiles are in use or stale; only their existence is counted.",
    fact: "endpoint.profile_count",
  },
  {
    id: "ff-sanitize", layer: "endpoint", targets: ["firefox"], kind: "bespoke", operation: "static", severities: ["ok", "info"],
    observes: "privacy.clearOnShutdown.* prefs and the sanitize flag",
    does_not_cover: "What happens on a hard kill; an unclean exit skips shutdown clearing entirely.",
    fact: "endpoint.clear_on_shutdown",
  },
  /* ---------------------------------------------------------------------
   * Hand-off target: what would travel with a directory about to be given
   * to someone else. All of these are catalog data -- the tree-match probe
   * is the only new shape, and onion client authorization is answered by
   * the Tor checks already in this table rather than by anything here.
   * ------------------------------------------------------------------- */
  {
    id: "handoff-secret-material", layer: "crypto", targets: ["handoff"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "handoff_root",
      patterns: [
        "^id_(rsa|dsa|ecdsa|ed25519)$", ".*\\.pem$", ".*\\.key$", ".*\\.p12$", ".*\\.pfx$", ".*\\.jks$",
        ".*\\.kdbx$", ".*\\.ovpn$", "^\\.env(\\..+)?$", "^\\.netrc$", "^credentials(\\.json|\\.yml|\\.yaml)?$",
        "^secring\\.gpg$", "^.*_rsa$", "^.*_ed25519$", "^known_hosts$",
      ],
      max_names: 12,
    },
    title: "Found {count} file name(s) that look like key material or credentials",
    detail: "Names like these travel with the directory. Whether they still contain anything usable is a separate question, but a hand-off should not be the moment that gets decided.",
    observes: "file NAMES anywhere under the hand-off root, to a bounded depth",
    does_not_cover: "File CONTENTS. A key pasted into notes.txt, or a password in a spreadsheet, is invisible to a name match -- and that is the common case.",
    fact: "crypto.handoff_secret_names",
  },
  {
    id: "handoff-editor-residue", layer: "metadata", targets: ["handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "handoff_root",
      patterns: [
        "^Thumbs\\.db$", "^desktop\\.ini$", "^\\.DS_Store$", "^\\.directory$", "^\\.Spotlight-V100$",
        ".*~$", ".*\\.swp$", ".*\\.swo$", ".*\\.bak$", ".*\\.orig$", ".*\\.rej$", ".*\\.tmp$",
      ],
      max_names: 12,
    },
    title: "Found {count} editor or filesystem residue file(s)",
    detail: "Backups, swap files and OS bookkeeping. Mostly harmless, but they are files nobody chose to send, and {count} of them is the sort of thing worth a second look before handing the directory over.",
    observes: "file NAMES matching editor and OS residue patterns, anywhere under the hand-off root",
    does_not_cover: "Whether any particular one contains anything sensitive; that needs the file's contents, which this tool does not read.",
    fact: "metadata.handoff_editor_residue",
  },
  {
    id: "handoff-vcs-internals", layer: "metadata", targets: ["handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "handoff_root",
      patterns: ["^\\.git$", "^\\.hg$", "^\\.svn$", "^\\.gitignore$", "^\\.git-credentials$"],
      match_dirs: true,
      max_names: 8,
    },
    title: "Found {count} version-control entry(ies)",
    detail: "A repository directory carries every revision, including the ones that were deleted from the working tree, and .git/config can carry a credential-bearing remote URL. Fine to send deliberately; worth noticing if it was not deliberate.",
    observes: "directory and file NAMES matching version-control patterns, anywhere under the hand-off root",
    does_not_cover: "What the history contains. A secret committed and later removed is still in the objects of a .git directory.",
    fact: "metadata.handoff_vcs",
  },
  {
    id: "handoff-build-residue", layer: "build", targets: ["handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "handoff_root",
      patterns: [
        "^node_modules$", "^__pycache__$", "^target$", "^dist$", "^build$", "^\\.venv$", "^venv$",
        "^\\.next$", "^\\.cache$", "^vendor$", ".*\\.pyc$", ".*\\.o$", ".*\\.class$",
      ],
      match_dirs: true,
      max_names: 8,
    },
    title: "Found {count} build or dependency artefact(s)",
    detail: "Compiled and fetched output. It bloats the hand-off, it may embed absolute paths from the machine that produced it, and anything generated is reproducible rather than worth sending.",
    observes: "directory and file NAMES matching build and dependency patterns, anywhere under the hand-off root",
    does_not_cover: "Whether a given artefact embeds an absolute path or a credential; that needs the file's contents.",
    fact: "build.handoff_build_residue",
  },
  {
    id: "handoff-onionshare", layer: "transport", targets: ["handoff"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.PATH_LIST,
    probe_args: {
      mode: "any-present",
      paths: [
        "{home}/AppData/Local/OnionShare", "{home}/AppData/Roaming/OnionShare",
        "{home}/Library/Application Support/OnionShare", "{home}/.config/OnionShare",
        "/Applications/OnionShare.app", "/usr/bin/onionshare", "/usr/bin/onionshare-cli",
        "/usr/share/applications/org.onionshare.OnionShare.desktop",
      ],
    },
    title: "OnionShare is present ({count} location(s))",
    detail: "A share can be started offline from this machine, which is the point: the file never passes through a third party and the receiver needs no account.",
    observes: "a fixed list of OnionShare install and configuration locations",
    does_not_cover: "Whether it runs, what version it is, or which onions it has shared. This is a presence check on paths, nothing more.",
    fact: "transport.handoff_onionshare",
  },

  /* -------------------------------------------------------------------
   * The sessions target: what the browser-automation toolchains left on disk.
   *
   * A different question from the hand-off target, and a different reason for reaching for the
   * tree-match probe. A hand-off asks "what would travel with this directory". This asks "what is
   * already on this machine that turns a copy of a folder into a live account" -- and the answer
   * is not the browser's configuration, which the firefox target already covers, but the files
   * the automation frameworks write out: Playwright's storage state, a cookie jar, an HTTP
   * archive, the profile directory a persistent context was handed.
   *
   * None of the five frameworks reports where those files went or what a copy is worth, which is
   * the entire reason this target exists.
   *
   * Severity follows what a leak yields rather than how unusual the file is. A plaintext session
   * export is critical because it IS a working credential; a profile store is a warning because it
   * is the same credential behind a key that lives in the directory beside it.
   * ------------------------------------------------------------------- */
  {
    id: "sessions-plaintext-session-export", layer: "crypto", targets: ["sessions"], kind: "builtin", operation: "static", severities: ["critical"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "sessions_root",
      patterns: [
        "^storage_?state.*\.json$", "^.*storage_?state.*\.json$",
        "^cookies\.txt$", "^cookie.*\.txt$", "^.*cookies.*\.json$",
      ],
      max_names: 12,
    },
    title: "Found {count} session export(s) stored in the clear",
    detail: "Playwright's storage state and a Netscape-style cookie jar are plaintext by design: cookies, localStorage and bearer tokens, readable by anything that can read the file. This is the shape that turns a copy of a folder into a live account.",
    observes: "file NAMES anywhere under a scanned root, to a bounded depth",
    does_not_cover: "Whether the session still works, and which origins it covers. The file is never opened, so an export that expired last year is reported exactly as loudly as a live one.",
    fact: "crypto.sessions_plaintext_exports",
  },
  {
    id: "sessions-http-archive", layer: "crypto", targets: ["sessions"], kind: "builtin", operation: "static", severities: ["critical"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: { base: "sessions_root", patterns: ["^.*\.har$"], max_names: 12 },
    title: "Found {count} HTTP archive(s)",
    detail: "A HAR records full request and response headers for every exchange it captured -- Authorization, Cookie, Set-Cookie -- and bodies besides. A recorded login is a recorded credential.",
    observes: "file NAMES anywhere under a scanned root, to a bounded depth",
    does_not_cover: "Whether the capture contains an authenticated exchange at all. A HAR of public pages is still a HAR, and this cannot tell the two apart without opening it.",
    fact: "crypto.sessions_http_archives",
  },
  {
    id: "sessions-profile-store", layer: "crypto", targets: ["sessions"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "sessions_root",
      patterns: [
        "^Cookies$", "^cookies\.sqlite$", "^Login Data$", "^Login Data For Account$",
        "^Local State$", "^key4\.db$", "^key[0-9]\.db$", "^logins\.json$", "^signons\.sqlite$",
      ],
      max_names: 16,
    },
    title: "Found {count} browser profile store(s)",
    detail: "A profile directory is a credential store, not a cache. Cookies and saved logins are encrypted with a key that sits beside them -- Chrome keeps it in Local State, Firefox in key4.db -- so anything running as this user can read them. That is what a foothold is.",
    observes: "file NAMES anywhere under a scanned root, to a bounded depth",
    does_not_cover: "Whether the key beside these stores is actually readable on this account, and whether the profile belongs to an automation run or to a browser you use by hand.",
    fact: "crypto.sessions_profile_stores",
  },
  {
    id: "sessions-profile-dir", layer: "metadata", targets: ["sessions"], kind: "builtin", operation: "static", severities: ["warn"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "sessions_root",
      match_dirs: true,
      patterns: ["^user-?data(-dir)?$", "^\.auth$", "^.*-userdata$", "^pw-.*profile.*$", "^.*automation.*profile.*$"],
      max_names: 12,
    },
    title: "Found {count} directory that looks like an automation profile",
    detail: "These are the names the frameworks pass to a persistent-context launch. The directory itself is the finding: everything the session accumulated -- cookies, storage, extensions, downloads -- lives inside it.",
    observes: "DIRECTORY NAMES anywhere under a scanned root, to a bounded depth",
    does_not_cover: "Whether such a directory is in use, and whether it was written by a framework or merely named that way by a person.",
    fact: "metadata.sessions_profile_dirs",
  },
  {
    id: "sessions-automation-artifact", layer: "metadata", targets: ["sessions"], kind: "builtin", operation: "static", severities: ["info"],
    probe: BUILTIN_PROBES.TREE_MATCH,
    probe_args: {
      base: "sessions_root",
      match_dirs: true,
      patterns: ["^playwright-report$", "^test-results$", "^.*trace.*\.zip$"],
      max_names: 12,
    },
    title: "Found {count} automation report or trace artifact(s)",
    detail: "Reports and traces carry screenshots, page URLs, console output and often recorded network bodies. They are the most readable record of what a session did, which is exactly why they should not be left where a copy of the folder would take them.",
    observes: "file and directory NAMES anywhere under a scanned root, to a bounded depth",
    does_not_cover: "Whether the artifacts are current or were already pruned, and what they contain. Nothing here opens them.",
    fact: "metadata.sessions_artifacts",
  },

  /* -------------------------------------------------------------------
   * The triage target: foothold artefacts, and the judgements over them.
   *
   * `bespoke` rather than `builtin`, for the reason the catalog header gives: these are not one
   * probe over one input. Each is a JUDGEMENT over the artefacts of five surfaces at once -- an
   * autostart whose target sits where anything can be written, a crash report from outside the
   * standard directories, a window in which several mechanisms agree. The evidence is a set of
   * entries from different readers, which is not a shape the probe vocabulary has, and forcing it
   * into one would mean inventing a probe only this target could use.
   *
   * They are catalogued all the same, because the alternative is worse: an id a reader cannot look
   * up is an id whose severity contract and boundary live only in the code that emitted it.
   * ------------------------------------------------------------------- */
  {
    id: "triage-autostart-user-writable", layer: "endpoint", targets: ["triage"], kind: "bespoke", operation: "static", severities: ["warn"],
    title: "An autostart entry points into a location any process can write to",
    observes: "the command of every startup-folder item, scheduled task, Run key and automatic service, with environment variables expanded, checked against the directories that need no elevation to write to",
    does_not_cover: "Whether the file is malicious, what it does, or who put it there. Nothing in this pass is opened and no command is executed, and legitimate updaters live in the same directories.",
    fact: "endpoint.triage_autostart",
  },
  {
    id: "triage-crash-outside-program-files", layer: "endpoint", targets: ["triage"], kind: "bespoke", operation: "static", severities: ["info"],
    title: "A crash report names an executable outside the standard program directories",
    observes: "the AppPath of every WER report under the user's reporting queues",
    does_not_cover: "Whether the crash was caused by the program or by something else, and whether the file still exists. Most of these are ordinary third-party software.",
    fact: "endpoint.triage_crashes",
  },
  {
    id: "triage-correlated-window", layer: "endpoint", targets: ["triage"], kind: "bespoke", operation: "static", severities: ["info"],
    title: "Several kinds of artefact appear together inside one window",
    observes: "the aligned timeline of all five surfaces, clustered by time and kept only where more than one source is present",
    does_not_cover: "What happened in the window, or whether the pieces are related at all. A software update produces the same shape.",
    fact: "endpoint.triage_clusters",
  },
  {
    id: "triage-guard-disabled", layer: "endpoint", targets: ["triage"], kind: "bespoke", operation: "static", severities: ["critical"],
    title: "A Windows security setting is switched off",
    observes: "Defender's own policy and state values, read from the registry",
    does_not_cover: "Who changed it or why, and whether anything is currently on the machine. A guard that is off is a fact; what it implies is not.",
    fact: "endpoint.triage_guard",
  },
  /* ------------------------------------------------ content
   *
   * The one target whose checks read BYTES. Each entry carries the matcher and the pattern where the
   * others carry a probe name, because the matcher vocabulary is closed and lives in lib/content.mjs:
   * a literal string, a byte sequence in hex, or a whole-file digest. Evaluation is bespoke (that
   * module owns it), so these entries declare the surface without the built-in probe runner having to
   * know anything about them -- and the ids written here are the ids the report emits, which is what
   * lets a baseline key on them exactly like every other finding.
   */
  {
    id: "private-key-header", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["critical"],
    matcher: "literal", pattern: "-----BEGIN ",
    title: "A PEM-style block header appears in a file's contents",
    detail: "PEM headers are how key material is stored as text. The block may be a public certificate, which is harmless, so the finding says look at this file rather than this file is a leak.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "It does not read far enough to tell a private key from a public certificate, and it cannot tell whether the file was ever committed, copied or sent.",
    fact: "crypto.content_pem_headers",
  },
  {
    id: "openssh-private-key", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["critical"],
    matcher: "literal", pattern: "-----BEGIN OPENSSH PRIVATE KEY-----",
    title: "An OpenSSH private key is stored in the clear",
    detail: "Unambiguous by its own header: the block names a private key. If it sits in a directory that travels, the key travels with it.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "It cannot tell whether the key is still valid anywhere, and it does not check whether a passphrase protects it.",
    fact: "crypto.content_openssh_keys",
  },
  {
    id: "putty-private-key", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["critical"],
    matcher: "literal", pattern: "PuTTY-User-Key-File-",
    title: "A PuTTY private key file is present",
    detail: "PuTTY stores its own key format as text, where it is easy to mistake for a configuration file.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "It does not attempt to decrypt, validate or use the key.",
    fact: "crypto.content_putty_keys",
  },
  {
    id: "aws-access-key-id", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["warn"],
    matcher: "literal", pattern: "AKIA",
    title: "A string shaped like an AWS access key id appears",
    detail: "Four letters is a weak signal on its own, which is why this entry may report a warning and never a critical. It earns its place because a key id left without its secret is what a careless copy looks like.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "It cannot recognise the matching secret key, cannot tell a live key from an example string in a document, and does not call any API to find out.",
    fact: "crypto.content_aws_key_ids",
  },
  {
    id: "github-token-shape", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["warn"],
    matcher: "literal", pattern: "ghp_",
    title: "A string shaped like a GitHub personal access token appears",
    detail: "The same reasoning as the access key id: a shape worth noticing, and not proof of anything.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "It does not validate the token, and the same prefix appears in documentation as an example.",
    fact: "crypto.content_github_tokens",
  },
  {
    id: "telegram-bot-token-shape", layer: "crypto", targets: ["content"], kind: "bespoke", operation: "static", severities: ["warn"],
    matcher: "literal", pattern: "AAH", disabled: true,
    title: "A three-letter fragment that also begins some bot tokens",
    detail: "Kept in the catalog on purpose and disabled by default, as a demonstration of how weak a literal can be. A rule table is data a reader is meant to argue with, and one entry arguing against itself is clearer than a comment claiming that some entries are weak.",
    observes: "the first max_bytes of a file the caller named",
    does_not_cover: "Essentially cannot distinguish a bot token from any other three characters in sequence, which is why it reports nothing unless it is explicitly enabled.",
    fact: "crypto.content_bot_token_fragments",
  },
  /* ------------------------------------------------ attribution
   *
   * The only target whose subject is OUTSIDE this machine. Its checks answer what a registry record
   * says about a name or a number, which is why the takedown report carries a section listing what it
   * does not claim: an id here is graded by the SOURCE of a record, never by how much it suggests.
   */
  {
    id: "attribution-target-kind-unknown", layer: "metadata", targets: ["attribution"], kind: "bespoke", operation: "static", severities: ["info"],
    title: "A target's shape is not one a registry route can be built for",
    detail: "Guessing what the string meant would produce a report about something else. A person can say what the target is; a tool cannot infer it.",
    observes: "the shape of each target string the caller named",
    does_not_cover: "Whether the target is real, reachable or of any interest -- only that its shape is not a domain, an address, an ASN or an email.",
    fact: "metadata.attribution_unknown_targets",
  },
  {
    id: "attribution-tld-not-in-table", layer: "metadata", targets: ["attribution"], kind: "bespoke", operation: "static", severities: ["info"],
    title: "No RDAP base is recorded here for this TLD",
    detail: "The bootstrap table bundled with this tool covers a fixed list with a stated date. The authoritative list is IANA's, and the report names it rather than presenting a snapshot as current.",
    observes: "the TLD of each domain or email target, against the table in lib/attribution.mjs",
    does_not_cover: "Whether an RDAP service exists for that TLD -- only that this tool does not know its address, so the public redirector is named instead.",
    fact: "metadata.attribution_unmapped_tlds",
  },
  {
    id: "attribution-no-abuse-channel", layer: "metadata", targets: ["attribution"], kind: "bespoke", operation: "static", severities: ["info"],
    title: "No abuse channel can be derived locally for this target",
    detail: "For this kind of target, every channel this tool can name depends on a record it has not read -- which is the case a lookup answers and an assumption does not.",
    observes: "the target kind, and the channels derivable without reading a registry record",
    does_not_cover: "Whether a channel exists. It says none is derivable from what is here, not that the operator has none.",
    fact: "metadata.attribution_channel_gaps",
  },
];

/* =====================================================================
];

/* ------------------------------------------------ lookup */

const BY_ID = new Map(CHECK_CATALOG.map((c) => [c.id, c]));

/** One catalog entry by id, or null. */
export function checkById(id) {
  return BY_ID.get(id) ?? null;
}

/**
 * The declared surface, optionally narrowed by target and layer.
 * Unknown filters are reported as `unmatched` rather than silently returning nothing.
 */
export function checksFor({ target, layer } = {}) {
  const wantTarget = typeof target === "string" && target !== "auto" ? target : null;
  const wantLayer = typeof layer === "string" && layer !== "all" ? layer : null;
  const out = CHECK_CATALOG.filter(
    (c) => (!wantTarget || c.targets.includes(wantTarget)) && (!wantLayer || c.layer === wantLayer)
  );
  return {
    total: CHECK_CATALOG.length,
    matched: out.length,
    target: wantTarget,
    layer: wantLayer,
    checks: out,
  };
}

/**
 * Structural digest: ids, layers, targets, kinds, severity contracts and fact paths --
 * deliberately NOT the prose. Baselines record this so that editing a description does not
 * invalidate a stored baseline, while adding, removing or re-scoping a check does.
 */
export function catalogDigest() {
  const structural = CHECK_CATALOG.map((c) => ({
    id: c.id,
    layer: c.layer,
    targets: [...c.targets].sort(),
    kind: c.kind,
    severities: [...c.severities].sort(),
    fact: c.fact ?? null,
    probe: c.probe ?? null,
  }));
  structural.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return createHash("sha256").update(JSON.stringify(structural)).digest("hex").slice(0, 16);
}

/* ------------------------------------------------ conformance */

/**
 * Check the findings a run produced against the catalog.
 *
 * `unknown` and `severity_violations` mean the code and the catalog disagree, which is a
 * defect in this repository rather than in the audited machine. `unfired` is informational:
 * a check that did not fire is normal (its subject was absent), and it is reported so that a
 * check which can never fire is at least visible.
 */
export function validateFindings(findings, { target } = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const unknown = [];
  const severity_violations = [];
  const fired = new Set();

  for (const f of list) {
    const id = f?.id;
    fired.add(id);
    const entry = BY_ID.get(id);
    if (!entry) { unknown.push(id); continue; }
    if (target && !entry.targets.includes(target)) {
      unknown.push(id);
      continue;
    }
    if (!entry.severities.includes(f.severity)) {
      severity_violations.push({ id, severity: f.severity, allowed: entry.severities });
    }
  }

  const applicable = target ? CHECK_CATALOG.filter((c) => c.targets.includes(target)) : CHECK_CATALOG;
  // Families registered once per member are listed by their own id, so a plain set difference
  // is enough; nothing here needs to know that cache-* share a loop.
  const unfired = applicable.filter((c) => !fired.has(c.id)).map((c) => c.id);

  return {
    checked: list.length,
    unknown: [...new Set(unknown)].sort(),
    severity_violations,
    unfired,
    conformant: unknown.length === 0 && severity_violations.length === 0,
  };
}

/* ------------------------------------------------ facts */

const setPath = (obj, dotted, value) => {
  const parts = dotted.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) cur[parts[i]] = {};
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
};

/**
 * Build the judgement-free fact record out of the evidence of the checks that fired.
 *
 * This is the "observed facts" surface: what the audit READ, as opposed to what it CONCLUDED.
 * Findings carry severity and opinion; facts carry neither, which is what makes the record
 * safe to compare, store, or query.
 *
 * A declared `fact` path names a SLOT, and the value placed in it is the check's whole
 * evidence object -- nothing is cherry-picked and nothing is synthesised, so every value in
 * the record can be traced straight back to the check that read it. The path is therefore a
 * stable schema name rather than a field path into the evidence.
 *
 * Each path is owned by exactly one check (asserted by the catalog tests). That is what makes
 * the record order-independent: with a shared path, whichever check happened to be evaluated
 * last would silently win.
 *
 * `layer` narrows the record the same way it narrows findings.
 */
export function factsFrom(findings, { layer } = {}) {
  const wantLayer = typeof layer === "string" && layer !== "all" ? layer : null;
  const facts = {};
  const sources = {};
  for (const f of Array.isArray(findings) ? findings : []) {
    const entry = BY_ID.get(f?.id);
    if (!entry?.fact) continue;
    if (wantLayer && f.layer !== wantLayer) continue;
    if (f.evidence === undefined) continue;
    setPath(facts, entry.fact, f.evidence);
    sources[entry.fact] = f.id;
  }
  return { facts, sources };
}

/**
 * Declared fact paths, so a test can prove no two checks own the same slot (a silent
 * overwrite would make the record depend on evaluation order).
 */
export function declaredFactPaths() {
  return CHECK_CATALOG.filter((c) => c.fact).map((c) => ({ id: c.id, fact: c.fact }));
}

/* =====================================================================
 * Built-in probes
 * ===================================================================== */

/**
 * Filesystem magics that PROVE a volume cannot carry whole-disk encryption: a FAT/exFAT
 * volume has no room for the container metadata such an encryption scheme needs.
 * Reported by statfs on POSIX; libuv leaves the field at 0 on Windows, which is why the
 * Windows path reports undetermined instead of guessing.
 */
export const VOLUME_MAGICS = {
  0x4d44: "FAT",
  0x2011bab0: "exFAT",
};

const PLAIN_BLOCK_DEVICE = /^\/dev\/(sd|hd|vd|nvme\d+n\d+|mmcblk\d+|xvd)/;
const MAPPED_DEVICE = /^\/dev\/(mapper|dm-)/;

/**
 * Classify whether the volume holding `root` is encrypted at rest.
 *
 * PURE on purpose: every input is passed in, so each branch is reachable from a test without
 * needing the matching platform. The caller does the reading.
 *
 * @param {{platform?:string, root?:string, mountInfo?:string|null, statfsType?:number|null}} input
 * @returns {{state:string, reason:string, detail:string, evidence:object}}
 */
export function classifyVolumeEncryption(input = {}) {
  const platform = input.platform ?? process.platform;
  const root = input.root ?? null;
  // An empty string means "the table was read and was empty"; null means "it could not be
  // read at all". Collapsing the two lets a missing mount table fall through to a positive
  // claim about the device, which is the one direction this must never guess in.
  const hasMountTable = typeof input.mountInfo === "string";
  const mountInfo = hasMountTable ? input.mountInfo : null;
  const statfsType = typeof input.statfsType === "number" && Number.isFinite(input.statfsType)
    ? input.statfsType : null;

  const evidence = { platform, root, signal: null, device: null, fs_type: null };

  if (hasMountTable) {
    const hit = longestMount(mountInfo, root);
    if (hit) {
      evidence.signal = "mount-table";
      evidence.device = hit.device;
      evidence.fs_type = hit.fsType;
      if (hit.fsType && /^crypto_/i.test(hit.fsType)) {
        return {
          state: "encrypted", reason: "crypto-filesystem",
          detail: `The mount table reports ${hit.device} as ${hit.fsType}, so this volume is encrypted at rest. Note that it is unlocked for as long as the machine is running, which is exactly when an audit can see it.`,
          evidence,
        };
      }
      if (MAPPED_DEVICE.test(hit.device)) {
        return {
          state: "encrypted", reason: "device-mapper",
          detail: `${hit.device} is a device-mapper target rather than a plain partition, which is the usual shape of an unlocked whole-disk container. The audit cannot tell which cipher or key is behind it.`,
          evidence,
        };
      }
      if (PLAIN_BLOCK_DEVICE.test(hit.device)) {
        return {
          state: "not-encrypted", reason: "plain-block-device",
          detail: `${hit.device} is a plain block device mounted directly as ${hit.fsType || "a filesystem"}. A filesystem mounted straight off a partition has no whole-disk layer underneath it, so this residue is readable by anyone who takes the disk.`,
          evidence,
        };
      }
      return {
        state: "undetermined", reason: "unrecognised-device",
        detail: `The mount table maps ${root} to ${hit.device} (${hit.fsType || "type unknown"}), which is neither a plain partition nor a mapped device. This audit does not guess.`,
        evidence,
      };
    }
    evidence.signal = "mount-table";
    return {
      state: "undetermined", reason: "no-mount-entry",
      detail: `No mount entry covers ${root ?? "the audit root"}; the volume backing it could not be identified from the mount table.`,
      evidence,
    };
  }

  if (statfsType !== null && VOLUME_MAGICS[statfsType]) {
    evidence.signal = "filesystem-magic";
    evidence.fs_type = VOLUME_MAGICS[statfsType];
    return {
      state: "not-encrypted", reason: "unencryptable-filesystem",
      detail: `The volume reports as ${VOLUME_MAGICS[statfsType]}. A ${VOLUME_MAGICS[statfsType]} filesystem cannot carry a whole-disk encryption container, so this residue is readable by anyone who takes the disk.`,
      evidence,
    };
  }

  if (platform === "win32") {
    evidence.signal = "none";
    return {
      state: "undetermined", reason: "windows-requires-elevation",
      detail:
        "On Windows the encryption state of a volume is not readable by a static, unprivileged audit: it lives behind BitLocker's WMI provider, " +
        "and this tool reads files without spawning anything. Run manage-bde -status from an elevated prompt to answer it by hand. " +
        "This is reported as undetermined rather than assumed to be fine.",
      evidence,
    };
  }

  evidence.signal = statfsType === null ? "none" : "filesystem-magic";
  evidence.fs_type = statfsType === null ? null : `unknown magic 0x${statfsType.toString(16)}`;
  return {
    state: "undetermined", reason: "no-signal",
    detail:
      `No usable signal for ${root ?? "the audit root"}: the filesystem type is ${evidence.fs_type ?? "unavailable"} and no mount entry was supplied. ` +
      "An unlocked container and an unencrypted volume look identical from here.",
    evidence,
  };
}

/**
 * Find the mount entry whose mount point is the longest prefix of `root`.
 * Longest-prefix matters: /home and / are both prefixes of /home/u, and picking the wrong one
 * reports the wrong device.
 */
function longestMount(mountInfo, root) {
  if (!root) return null;
  const norm = (p) => (p.length > 1 ? p.replace(/\/+$/, "") : p);
  const target = norm(root.replace(/\\/g, "/"));
  let best = null;
  for (const line of mountInfo.split("\n")) {
    // mountinfo: id parent major:minor root mountpoint options... - fstype source superopts
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const sep = f.indexOf("-");
    if (sep < 0 || sep + 2 >= f.length) continue;
    const mp = norm(f[4].replace(/\\040/g, " "));
    if (target !== mp && !target.startsWith(mp === "/" ? "/" : `${mp}/`)) continue;
    if (!best || mp.length > best.mountPoint.length) {
      best = { mountPoint: mp, fsType: f[sep + 1], device: f[sep + 2] };
    }
  }
  return best;
}

/** Exported for the catalog tests: which probe names the catalog actually references. */
export function declaredProbes() {
  return [...new Set(CHECK_CATALOG.filter((c) => c.probe).map((c) => c.probe))].sort();
}

/** Substitute `{name}`-style placeholders. Unknown keys are left visible on purpose. */
export function renderTemplate(text, vars) {
  return String(text).replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (whole, key) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : whole);
}

/**
 * Evidence for a residue finding.
 *
 * ONE shape for every path-residue check, deliberately. Three existed before the catalog did --
 * `size-mtime`, `path-age` and `cache` -- because three separate pieces of code had each built its
 * own, and unifying them at the same time as moving where the checks live would have left the
 * suites unable to tell a faithful migration from a broken one. The migration has since been
 * proven field-for-field against the previous commit, so collapsing them is a small, visible
 * decision rather than a hidden side effect.
 *
 * `stale` is gone rather than carried: it is derivable from `age_days` and the entry's own
 * threshold, and a recorded fact that can be recomputed is a fact that can disagree with its
 * input. `path` is now present everywhere, which the cache and Tor checks previously omitted.
 */
const residueEvidence = (r) => ({ path: r.rel, size: r.size, mtime: r.mtimeIso, age_days: r.age });

/**
 * Run one catalog entry against a context. Returns null when the check has nothing to report.
 *
 * Exported as well as used internally: evaluating a single entry is how a new probe can be
 * tested in isolation, and how a caller can dry-run one check without auditing a whole target.
 * An entry naming a probe this build does not implement returns null rather than throwing --
 * the catalog is data, and data can be wrong without the audit falling over.
 */
export function evaluateOneBuiltin(entry, ctx = {}) {
  // Guarded once, here, rather than per branch: the catalog is data, and a null or malformed
  // entry must produce no finding instead of taking the audit down. Guarding only the first
  // branch was the mistake the suite caught -- a null entry reached the second one and threw.
  if (entry === null || typeof entry !== "object") return null;
  const args = entry.probe_args ?? {};
  const io = ctx.io ?? {};
  const bases = ctx.bases ?? {};

  if (entry.probe === BUILTIN_PROBES.VOLUME_ENCRYPTION) {
    const r = classifyVolumeEncryption(ctx);
    return {
      layer: entry.layer,
      id: entry.id,
      severity: r.state === "encrypted" ? "ok" : r.state === "not-encrypted" ? "warn" : "info",
      title:
        r.state === "encrypted" ? "Volume is encrypted at rest (determined)"
        : r.state === "not-encrypted" ? "Volume is not encrypted at rest (determined)"
        : "Volume encryption could not be determined",
      detail:
        r.detail +
        " This concerns the volume as a whole, so it applies to every file on it, not only to this target.",
      evidence: { state: r.state, reason: r.reason, ...r.evidence },
    };
  }

  if (entry.probe === BUILTIN_PROBES.PATH_RESIDUE) {
    const dir = bases[args.base];
    if (typeof dir !== "string" || !dir) return null;
    const full = path.join(dir, args.file);
    const st = io.statOf ? io.statOf(full) : null;
    if (!st || st.size < (args.min_size ?? 1)) return null;
    const age = daysSince(st.mtime);
    const stale = args.stale_days != null && age != null && age > args.stale_days;
    const vars = {
      name: args.name ?? args.file,
      size: fmtBytes(st.size),
      age,
      path: args.file,
      mtime: st.mtime.toISOString(),
    };
    return {
      layer: entry.layer,
      id: entry.id,
      severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, vars),
      detail: renderTemplate(stale && entry.detail_if_stale ? entry.detail_if_stale : entry.detail, vars),
      evidence: { ...residueEvidence({ rel: args.file, size: st.size, mtimeIso: st.mtime.toISOString(), age }), abs: full },
    };
  }

  if (entry.probe === BUILTIN_PROBES.DIR_ENTRIES || entry.probe === BUILTIN_PROBES.DIR_SIZE) {
    const dir = bases[args.base];
    if (typeof dir !== "string" || !dir) return null;
    // `file` is optional: a base may already BE the directory of interest (a keys directory),
    // in which case joining an empty name would be a no-op that reads as if it did something.
    const full = args.file ? path.join(dir, args.file) : dir;
    if (entry.probe === BUILTIN_PROBES.DIR_SIZE) {
      const total = io.dirSize ? io.dirSize(full) : null;
      if (total == null || total < (args.min_size ?? 1)) return null;
      return {
        layer: entry.layer, id: entry.id, severity: args.severity ?? entry.severities[0],
        title: renderTemplate(entry.title, { size: fmtBytes(total) }),
        detail: renderTemplate(entry.detail, { size: fmtBytes(total) }),
        evidence: { size: total },
      };
    }
    const all = (io.listDir ? io.listDir(full) : []).filter((e) => e.isFile());
    const matched = args.pattern ? all.filter((e) => new RegExp(args.pattern, "i").test(e.name)) : all;
    // A max_count of 0 is how "the directory is configured but empty" is expressed; min_count
    // covers its complement. Both are ordinary fields rather than two probe kinds.
    if (matched.length < (args.min_count ?? 1)) return null;
    if (args.max_count != null && matched.length > args.max_count) return null;
    const names = matched.map((e) => e.name);
    const vars = { count: matched.length, name: args.file, dir };
    let evidence;
    if (args.evidence === "entries") evidence = { dir: full, entries: names.slice(0, args.max_names ?? 10) };
    else if (args.evidence === "dir-only") evidence = { dir: full };
    else if (args.evidence === "session") {
      const newest = matched.map((e) => (io.statOf ? io.statOf(path.join(full, e.name)) : null))
        .filter(Boolean).sort((a, b) => b.mtime - a.mtime)[0];
      evidence = { count: matched.length, newest: newest ? newest.mtime.toISOString() : null };
    } else evidence = { files: names.slice(0, args.max_names ?? 10) };
    return {
      layer: entry.layer,
      id: entry.id,
      severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, vars),
      detail: renderTemplate(entry.detail, vars),
      evidence,
    };
  }

  if (entry.probe === BUILTIN_PROBES.PATH_LIST) {
    // Every candidate path is tried; the check is about how many of them exist. `{home}` and
    // `{tmp}` come from the context, so the list itself is data and the platform differences
    // stay in the caller that knows them.
    const candidates = (args.paths ?? []).map((p) => renderTemplate(p, { home: bases.home ?? "", tmp: bases.tmp ?? "" }));
    const hit = candidates.filter((p) => {
      if (args.exclude_equal_to && bases[args.exclude_equal_to] &&
          path.resolve(p).toLowerCase() === path.resolve(bases[args.exclude_equal_to]).toLowerCase()) return false;
      return io.exists ? io.exists(p) : false;
    });
    if (args.mode === "none-present") {
      if (hit.length !== 0) return null;
      return {
        layer: entry.layer, id: entry.id, severity: args.severity ?? entry.severities[0],
        title: renderTemplate(entry.title, { count: 0, checked: bases.home ?? "" }),
        detail: renderTemplate(entry.detail, { checked: bases.home ?? "" }),
        evidence: { checked: bases.home ?? null },
      };
    }
    if (hit.length === 0) return null;
    return {
      layer: entry.layer, id: entry.id, severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, { count: hit.length }),
      detail: renderTemplate(entry.detail, { count: hit.length }),
      evidence: { traces: hit },
    };
  }

  if (entry.probe === BUILTIN_PROBES.JSON_FIELD) {
    const dir = bases[args.base];
    if (typeof dir !== "string" || !dir) return null;
    const doc = io.readJson ? io.readJson(path.join(dir, args.file)) : null;
    if (!doc || typeof doc !== "object") return null;
    // The check fires whenever the document parses, even with neither field present -- that is
    // what the code this replaced did, and fmtTime renders an absent time as "-" rather than
    // dropping the finding. Requiring a field here would have changed when the check runs.
    const first = doc[args.primary] ?? doc[args.fallback];
    return {
      layer: entry.layer, id: entry.id, severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, { time: fmtTime(first) }),
      detail: renderTemplate(entry.detail, { time: fmtTime(first) }),
      evidence: { first_use: doc[args.primary] ?? null, created: doc[args.fallback] ?? null, abs: path.join(dir, args.file) },
    };
  }

  if (entry.probe === BUILTIN_PROBES.TREE_MATCH) {
    // A recursive name match, which is the one shape a hand-off scan needs and nothing else
    // provided: residue is scattered through a tree rather than sitting at a known path, so a
    // fixed candidate list -- what path-list is -- cannot find it.
    //
    // Bounded on purpose. The directory being handed over is arbitrary and may be enormous, so the
    // walk stops at a depth and an entry count, and it SAYS SO in its evidence. A partial scan
    // reported as a complete one would be the worst possible behaviour for a tool whose whole
    // output is an assurance about what is in a directory.
    const root = bases[args.base];
    if (typeof root !== "string" || !root) return null;
    if (!(io.exists ? io.exists(root) : false)) return null;

    const maxEntries = args.max_entries ?? 20000;
    const maxDepth = args.max_depth ?? 8;
    const patterns = (args.patterns ?? []).map((p) => new RegExp(p, "i"));
    const skip = (args.skip_dirs ?? []).map((p) => new RegExp(p, "i"));
    const matchDirs = args.match_dirs === true;

    let visited = 0;
    let truncated = false;
    // The depth bound stops the walk silently no matter what `truncated` says, which is the one
    // thing this probe's own comment calls the worst possible behaviour for it: a partial tree
    // reported as a complete one. The two bounds are counted separately so a reader can tell WHY
    // the answer is partial -- an entry budget that ran out is a different problem from a tree
    // that goes deeper than the walk was allowed to follow.
    let depthLimited = false;
    const hits = [];
    const record = (rel, full) => {
      const st = io.statOf ? io.statOf(full) : null;
      hits.push({ path: rel, size: st ? st.size : null, mtime: st ? st.mtime.toISOString() : null });
    };
    const walk = (dir, rel, depth) => {
      if (truncated) return;
      if (depth > maxDepth) { depthLimited = true; return; }
      for (const e of (io.listDir ? io.listDir(dir) : [])) {
        if (visited >= maxEntries) { truncated = true; return; }
        visited += 1;
        const childRel = rel ? rel + "/" + e.name : e.name;
        const full = path.join(dir, e.name);
        const isDir = !!(e.isDirectory && e.isDirectory());
        const named = patterns.some((r) => r.test(e.name));
        if (isDir) {
          // A matching directory is recorded AND descended into: .git is the finding, and what is
          // inside it is where a second one would be.
          if (matchDirs && named && !skip.some((r) => r.test(e.name))) record(childRel + "/", full);
          if (!skip.some((r) => r.test(e.name))) walk(full, childRel, depth + 1);
          continue;
        }
        if (named) record(childRel, full);
      }
    };
    walk(root, "", 0);

    if (hits.length < (args.min_count ?? 1)) return null;
    return {
      layer: entry.layer,
      id: entry.id,
      severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, { count: hits.length }),
      detail: renderTemplate(entry.detail, { count: hits.length }),
      evidence: {
        root,
        matched: hits.length,
        scanned: visited,
        // `truncated` is the answer a caller acts on: the walk did not cover everything it was
        // pointed at. `depth_limited` says which bound was responsible.
        truncated: truncated || depthLimited,
        depth_limited: depthLimited,
        entries: hits.slice(0, args.max_names ?? 12),
      },
    };
  }

  if (entry.probe === BUILTIN_PROBES.STATIC) {
    // No reads at all: the check is a statement about the shape of the install, with the
    // install's own path as its evidence. Data because there is nothing to compute.
    const vars = { root: bases.install_root ?? "", profile_dir: bases.profile_dir ?? "" };
    return {
      layer: entry.layer, id: entry.id, severity: args.severity ?? entry.severities[0],
      title: renderTemplate(entry.title, vars),
      detail: renderTemplate(entry.detail, vars),
      evidence: renderEvidence(args.evidence, vars),
    };
  }

  if (entry.probe === BUILTIN_PROBES.CONFIG_VALUE) {
    // `base` reads the symbolic base map, `torrc` the merged torrc entries, `prefs` a Firefox
    // prefs object. Letting a check read a base is what keeps a configured/absent pair honest:
    // onion-auth-absent and onion-auth-empty both key off the same auth_dir base, so they cannot
    // disagree about whether the directory is configured -- which they could when one read the
    // torrc and the other read the base.
    const fromBase = args.source === "base";
    // A base-reading check needs the base map to have been SUPPLIED. An empty map means "this
    // target has no such configuration", while an absent map means the caller did not describe the
    // target at all -- and reporting "not configured" for the second would be inventing an answer.
    if (fromBase && !ctx.bases) return null;
    // require_base names a base that must be present for the check to answer at all. This is a
    // PRECONDITION, not a composed predicate: the variant vocabulary is deliberately closed and
    // single-key, and "the target was described, and this particular key is absent" is not a
    // question one predicate can ask.
    //
    // onion-auth-absent needs it because two different situations both look like an absent
    // auth_dir: a Tor install was examined and its torrc names no authorization directory, and no
    // Tor install was examined at all. Only the first is the claim that check makes. It appeared
    // the moment aikawamei_handoff reused these checks against a directory with no Tor behind it --
    // reporting "client authorization is not configured" for a machine where nothing had been
    // asked. The same class of defect as an empty mount table read as "no encryption" (D38).
    if (fromBase && args.require_base && !bases[args.require_base]) return null;
    const source = fromBase ? bases : (args.source === "torrc" ? ctx.entries : ctx.prefs);
    if (!source) return null;
    const keys = args.keys ?? {};
    const has = (k) => (fromBase
      ? Object.prototype.hasOwnProperty.call(source, k) && !!source[k]
      : Object.prototype.hasOwnProperty.call(source, k));
    const raw = (name) => {
      const k = keys[name];
      const v = source[k];
      // torrc values are stored as arrays; a single-valued entry is unwrapped so that a
      // predicate can compare it the way the code it replaced did.
      return Array.isArray(v) ? (v.length === 1 ? v[0] : v[0]) : v;
    };
    const vars = {};
    for (const name of Object.keys(keys)) {
      let v = raw(name);
      // A check may declare names to normalise to boolean-or-null, which is what the code it
      // replaced did with `asBoolOrNull`: a pref that is present but not a boolean reads as null
      // rather than as its own value, so the evidence shape does not quietly change.
      if ((args.booleans ?? []).includes(name)) v = typeof v === "boolean" ? v : null;
      vars[name] = v === undefined ? null : v;
      const labels = args.labels?.[name];
      if (labels) vars[`${name}_label`] = labels[String(v)] ?? `unknown (${v})`;
    }
    const chosen = (args.variants ?? []).find((v) => {
      if (v.always) return true;
      const name = v.key ?? Object.keys(keys)[0];
      const value = vars[name];
      const present = has(keys[name]);
      if (v.absent) return !present;
      if (v.present) return present;
      if (v.truthy) return present && !!raw(name);
      if (v.is_true) return value === true;
      if (v.is_false) return value === false;
      if (v.one_of) return present && v.one_of.map(String).includes(String(raw(name)));
      // Multi-key predicates are the only ones that look beyond one entry, and they take the
      // whole key map rather than a named subset. There is deliberately no way to combine two
      // predicates in one variant: that is where a data table would start being a language.
      if (v.any_true) return Object.keys(keys).some((n) => vars[n] === true);
      if (v.all_false) return Object.keys(keys).length > 0 && Object.keys(keys).every((n) => vars[n] === false);
      if (v.any_present) return Object.keys(keys).some((n) => has(keys[n]));
      return false;
    });
    if (!chosen) return null;
    return {
      layer: entry.layer, id: entry.id, severity: chosen.severity ?? args.severity ?? entry.severities[0],
      title: renderTemplate(chosen.title ?? entry.title, vars),
      detail: renderTemplate(chosen.detail ?? entry.detail, vars),
      evidence: renderEvidence(chosen.evidence ?? args.evidence, vars),
    };
  }

  return null;
}

/**
 * Render an evidence template: an object whose values are placeholders drawn from the probe's
 * vars. A literal that is not a placeholder is left alone, and a placeholder that resolves to
 * nothing becomes null rather than the string "undefined".
 */
function renderEvidence(template, vars) {
  if (template == null) return null;
  const out = {};
  for (const [k, v] of Object.entries(template)) {
    if (typeof v !== "string") { out[k] = v; continue; }
    const m = v.match(/^\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
    out[k] = m ? (vars[m[1]] ?? null) : renderTemplate(v, vars);
  }
  return out;
}

/**
 * FILES THIS TOOL IS WILLING TO REMOVE
 * ------------------------------------
 * Almost everything in this project reads. Collection copies, the vault appends, the self-check
 * writes a manifest -- each of those produces a second thing. Deletion is the only write that leaves
 * fewer files than it found, so the set is closed and written down here as data rather than decided
 * by a branch in some function.
 *
 * A check that is not in this table is reported and never removed. Three of the most valuable files
 * in a profile are deliberately absent: logins.json, key4.db and cert9.db hold saved logins and the
 * key material protecting them. There is no reading of "clean up the residue" that should quietly
 * sign somebody out of every account they have, and a deletion nobody asked for is worse than a
 * residue that stays.
 *
 * Each value says what removing that file COSTS. That is not decoration: it is the sentence a caller
 * reads before the file is gone, which is the only moment it can still change their mind.
 */
export const REMOVABLE = {
  "state-file":
    "state records guard selection, bridge usage and circuit build times. Removing it discards the guard set: Tor " +
    "selects a new one on the next launch, which is a different entry point than the accumulated one. The usage " +
    "timeline goes with it. Nothing else is affected.",
  places:
    "Browsing history and bookmarks are lost. Tor Browser rebuilds the database on the next launch; the history " +
    "inside it is not recoverable.",
  "session-checkpoints":
    "Window and tab restore state is lost. Nothing else.",
  "profile-times":
    "The recorded first-use time is lost and Firefox writes a new one on the next launch, dated then. That is a " +
    "reset, not an erasure -- the profile's creation is still visible in the timestamps around it.",
  "cache-cached-descriptors":
    "The relay cache is refetched from the directory authorities on the next launch. The cost is a slower first " +
    "connection; what is gained is that the cached set no longer dates this install's activity.",
  "cache-cached-microdescs":
    "The microdescriptor cache is refetched on the next launch. Slower first connection, and the accumulated list " +
    "of relays this install talked to is gone.",
  "cache-cached-microdescs.new":
    "A partially built cache. Removing it costs nothing measurable: Tor rebuilds it from the same source as the " +
    "finished one.",
  "cache-cached-certs":
    "Directory authority certificates, refetched on demand. Removing them costs one re-handshake.",
  "cache-cached-consensus":
    "The consensus snapshot, refetched on the next launch. Its only lasting value to an examiner is the date it " +
    "was written.",
  "ff-history":
    "Firefox history and bookmarks are lost. Firefox keeps this by design, so removing it removes the record, " +
    "not the ability to record.",
  "ff-cookies":
    "Saved sessions are lost: every site this profile was signed in to will ask again. Live cookies are " +
    "replayable, which is the reason to remove them.",
  "ff-permissions":
    "Per-site camera, microphone, geolocation and notification grants are lost and will be asked again.",
  "ff-formhistory":
    "Previously typed form values are lost, including anything entered into a field that was not marked as a " +
    "password field. There is no partial removal: the file goes as a whole.",
  "ff-favicons":
    "Site icons are lost. Firefox rebuilds them as sites are visited.",
};

/**
 * Run every built-in check the catalog declares for `target`, optionally narrowed to one layer.
 *
 * `ctx` is passed straight through to the probes, so this stays pure and a test can drive every
 * branch without touching the real filesystem.
 */
export function evaluateBuiltins(target, ctx = {}, opts = {}) {
  const wantLayer = typeof opts.layer === "string" && opts.layer !== "all" ? opts.layer : null;
  const out = [];
  for (const entry of CHECK_CATALOG) {
    if (entry.kind !== "builtin") continue;
    if (target && !entry.targets.includes(target)) continue;
    if (wantLayer && entry.layer !== wantLayer) continue;
    const r = evaluateOneBuiltin(entry, ctx);
    if (!r) continue;
    out.push(r);
  }
  return out;
}
