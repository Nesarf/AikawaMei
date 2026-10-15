/**
 * AikawaMei - attribution and takedown routing
 *
 * WHAT THIS ANSWERS, AND WHAT IT REFUSES TO ANSWER
 * ------------------------------------------------
 * The question this exists for is not "who did it". That question is the one an audit is least able
 * to answer honestly, and the project's own history has a case of getting it wrong: a lost account
 * was read as "there is an infostealer on this machine" when the evidence supported two independent
 * events. So the tool is built the other way round. It answers three smaller questions that can be
 * answered from records:
 *
 *   1. WHO IS RESPONSIBLE FOR THIS ADDRESS? A registry route for a domain, an IP or an ASN, with the
 *      bootstrap table written down as data rather than remembered.
 *   2. WHO CAN ACT ON IT? The abuse channels that exist for that address, each labelled as a
 *      candidate to confirm rather than as a fact, because "abuse@example.com" is a convention.
 *   3. HOW DOES A REPORT GET WRITTEN SO IT DOES NOT OVERCLAIM? An outline that carries the two
 *      sections most reports omit -- what this report does NOT claim, and what its sharing scope is.
 *
 * What it deliberately does not do, listed here because the omission is the design:
 *
 *   - it does not send anything. No email, no form, no webhook, no API call that files a report. It
 *     produces a local document and a list of channels; a person decides what leaves the machine.
 *   - it does not attribute a person, a group or a motive, and it does not grade an attribution as
 *     "likely" or "probable". Every grade it can emit names what the evidence IS, never how much it
 *     suggests. "Unattributable" is a first-class answer and the default whenever nothing holds.
 *   - it does not speak whois. Plain-text whois is a different protocol on a different port than
 *     anything this project already has a path to, so naming a whois server here is a REFERENCE for
 *     a human to use, not a capability claimed by a tool that cannot reach it.
 *   - it does not publish. Naming an operator publicly is not a step this tool can take, and the
 *     standing instruction for this work item rules out the exposure route entirely.
 *
 * NETWORK, AND WHY THE SWITCH IS OFF
 * ----------------------------------
 * Everything above is computed from tables in this file, with no network. RDAP over HTTPS is
 * available only when the caller passes `allow_lookup: true`, which is one explicit decision per
 * call, and the response records that the lookup happened, what was asked, and what came back. The
 * tool declares the `lookup` operation for exactly this reason: a boundary notice that said "never
 * touches the network" would be false here in a way the caller could not see.
 */



/**
 * The module imports no transport, and that is deliberate: `httpsGetJson` is NOT imported here. A
 * lookup function exists and takes its fetcher as a REQUIRED argument, so this file cannot reach the
 * network by itself under any configuration, and the suite can drive every branch without one. The
 * TOOL passes the transport and declares the `lookup` operation, which is where the boundary is
 * decided -- one file up, where a reader checking the declaration can see it.
 *
 * The commands are provided as well as the switch: a reader who would rather run the query by hand
 * gets the URL and a line for each shell on this machine, and the response says the tool did not run
 * it. Both are real answers; only one of them is the tool doing the reaching.
 */
export const ATTRIBUTION_SCHEMA = "aikawamei-attribution/1";
export const ATTRIBUTION_RULES_VERSION = "1";

/**
 * RDAP bootstrap, as data, for the TLDs this machine is most likely to need.
 *
 * Not a copy of IANA's bootstrap file, and not pretending to be: the authoritative file is at
 * https://data.iana.org/rdap/dns.json, it changes, and a tool that bundled a snapshot and called it
 * authoritative would be wrong within a year. What is here is a small table with a stated date, and
 * anything outside it is reported as undetermined together with the URL that answers it.
 */
export const RDAP_BOOTSTRAP = {
  as_of: "2026-10-15",
  authoritative: "https://data.iana.org/rdap/dns.json",
  redirector: "https://rdap.org",
  tlds: {
    com: "https://rdap.verisign.com/com/v1",
    net: "https://rdap.verisign.com/net/v1",
    org: "https://rdap.publicinterestregistry.org/rdap",
    info: "https://rdap.identitydigital.services/rdap",
    io: "https://rdap.identitydigital.services/rdap",
    dev: "https://rdap.nominet.uk/dev",
    app: "https://rdap.nominet.uk/app",
    me: "https://rdap.nic.me",
    jp: "https://rdap.jprs.co.jp",
    cn: "https://rdap.cnnic.cn",
    co: "https://rdap.nic.co",
    uk: "https://rdap.nominet.uk/uk",
    de: "https://rdap.denic.de",
    fr: "https://rdap.nic.fr",
    xyz: "https://rdap.centralnic.com/xyz",
    top: "https://rdap.centralnic.com/top",
  },
};

/**
 * What an evidence grade names: the SOURCE, never the weight. A reader who wants a probability is
 * reading the wrong field, and the report says so where it prints this table.
 */
export const EVIDENCE_GRADES = [
  { grade: "registry-record", meaning: "a registration record returned by the registry's own RDAP service", holder: "a lookup with allow_lookup, or a person reading the same URL" },
  { grade: "self-declared", meaning: "something the operator states about itself on a page it controls", holder: "an observation a person can repeat" },
  { grade: "dns-answer", meaning: "a record served by DNS for the name, which shows control of the name at that moment and nothing else", holder: "a resolution, which this tool does not perform" },
  { grade: "third-party-report", meaning: "a claim in someone else's report or blocklist, which is evidence that a claim exists", holder: "the report itself, quoted rather than summarized" },
  { grade: "unattributable", meaning: "nothing available supports naming an operator, and the honest output is this grade", holder: "the absence of the above, stated rather than omitted" },
];

/**
 * Traffic Light Protocol levels, with what each one permits. The report carries the level and this
 * sentence, because a TLP marking nobody can look up is decoration.
 */
export const TLP_LEVELS = [
  { level: "TLP:RED", permits: "the named recipients only, and no further sharing in any form" },
  { level: "TLP:AMBER+STRICT", permits: "the recipient organisation only; no sharing with its clients or customers" },
  { level: "TLP:AMBER", permits: "the recipient organisation and its clients on a need-to-know basis" },
  { level: "TLP:GREEN", permits: "the wider community, but not publication" },
  { level: "TLP:CLEAR", permits: "unrestricted sharing, including publication" },
];

/**
 * The section most takedown reports omit. Each line is a claim this report does NOT make, and they
 * are printed whether or not anything was found, because their absence reads as confidence.
 */
export const NOT_CLAIMABLE = [
  "that any particular person, group or organisation carried out an action",
  "why anything happened: this report carries no motive, and no motive is inferred from a target",
  "that two events are related because they happened close together in time",
  "that a host is the actor's own: infrastructure is routinely rented, compromised or shared",
  "that silence in this report means an absence of activity, rather than an absence of records",
];

/** The candidate shapes an abuse address is built from. Candidates, explicitly not facts. */
export const ABUSE_TEMPLATES = [
  { template: "abuse@{domain}", note: "the convention most operators follow, and only a convention" },
  { template: "abuse@{tld}-registry@...", note: "the registry's own abuse desk, when the registrant's is unresponsive" },
  { template: "the registrar named in the registration record", note: "the registrar is who can suspend a domain, which the registrant often cannot" },
  { template: "the hosting provider from the address's own records", note: "for an IP, this is usually the only channel that ends in action" },
];

/* ------------------------------------------------------------------ target classification */

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const ASN = /^as(\d+)$/i;
const EMAIL = /^[^\s@]+@[^\s@]+$/;

/** What kind of thing the caller handed us, decided from its shape and nothing else. */
export function classifyTargetKind(raw) {
  const t = String(raw ?? "").trim();
  if (!t) return "empty";
  if (ASN.test(t)) return "asn";
  if (IPV4.test(t)) {
    const parts = t.split(".").map(Number);
    if (parts.every((n) => n >= 0 && n <= 255)) return "ipv4";
    return "unknown";
  }
  if (t.includes(":") && /^[0-9a-fA-F:]+$/.test(t)) return "ipv6";
  if (EMAIL.test(t)) return "email";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(t)) return "domain";
  return "unknown";
}

/** The registrable part of a domain, as far as a table of two-label TLDs can tell. */
export function registrableDomain(domain) {
  const d = String(domain ?? "").toLowerCase().replace(/\.$/, "");
  const parts = d.split(".").filter(Boolean);
  if (parts.length <= 2) return d;
  const lastTwo = parts.slice(-2).join(".");
  if (RDAP_BOOTSTRAP.tlds[lastTwo]) return lastTwo;
  return lastTwo;
}

/* ------------------------------------------------------------------ routing */

/**
 * Where to ask, for one target. `rdap_url` is a URL this tool can fetch when a lookup is allowed;
 * `whois_reference` is a pointer for a human, and the response says plainly that the tool does not
 * speak that protocol.
 */
export function routeFor(raw) {
  const target = String(raw ?? "").trim();
  const kind = classifyTargetKind(target);
  const out = {
    target,
    kind,
    rdap_url: null,
    rdap_source: null,
    whois_reference: null,
    undetermined: null,
  };
  if (kind === "domain" || kind === "email") {
    const domain = kind === "email" ? target.split("@")[1] : target;
    const registrable = registrableDomain(domain);
    const tld = registrable.split(".").pop();
    const base = RDAP_BOOTSTRAP.tlds[tld] ?? null;
    if (base) {
      out.rdap_url = `${base.replace(/\/$/, "")}/domain/${encodeURIComponent(registrable)}`;
      out.rdap_source = `the bootstrap table in this file (as of ${RDAP_BOOTSTRAP.as_of})`;
    } else {
      out.rdap_url = `${RDAP_BOOTSTRAP.redirector}/domain/${encodeURIComponent(registrable)}`;
      out.rdap_source = "the public redirector, because this TLD is not in the table";
      out.undetermined = {
        what: `the RDAP base for .${tld} is not in this file's table`,
        answered_by: RDAP_BOOTSTRAP.authoritative,
        note: "the redirector above usually resolves it, and the authoritative answer is the IANA bootstrap file",
      };
    }
    out.whois_reference = { server: "whois.iana.org", query: registrable, note: "IANA's own referral server; this tool does not speak whois, so this is for a person" };
    out.registrable = registrable;
    return out;
  }
  if (kind === "ipv4" || kind === "ipv6") {
    out.rdap_url = `${RDAP_BOOTSTRAP.redirector}/ip/${encodeURIComponent(target)}`;
    out.rdap_source = "the public redirector, which routes to the RIR that holds the block";
    out.whois_reference = { server: "whois.iana.org", query: target, note: "the RIR is found from the referral; a person runs this" };
    return out;
  }
  if (kind === "asn") {
    const n = target.replace(/^as/i, "");
    out.rdap_url = `${RDAP_BOOTSTRAP.redirector}/autnum/${encodeURIComponent(n)}`;
    out.rdap_source = "the public redirector, which routes to the RIR that holds the number";
    return out;
  }
  out.undetermined = { what: "this target's shape is not one a registry route can be built for", answered_by: "a person, who can say what the target is" };
  return out;
}

/** The candidate channels for one target, each labelled as a candidate. */
export function abuseChannelsFor(raw) {
  const route = routeFor(raw);
  const channels = [];
  if (route.kind === "domain" || route.kind === "email") {
    const domain = route.kind === "email" ? String(raw).split("@")[1] : String(raw);
    channels.push({ channel: `abuse@${registrableDomain(domain)}`, basis: ABUSE_TEMPLATES[0].note, confirmed: false });
    channels.push({ channel: `abuse@${domain}`, basis: "the name as given, in case the subdomain runs its own desk", confirmed: false });
    channels.push({ channel: "the registrar named in the registration record", basis: ABUSE_TEMPLATES[2].note, confirmed: false });
    channels.push({ channel: "the registry for the TLD", basis: ABUSE_TEMPLATES[1].note, confirmed: false });
  } else if (route.kind === "ipv4" || route.kind === "ipv6" || route.kind === "asn") {
    channels.push({ channel: "the abuse contact the RIR publishes for this block or number", basis: ABUSE_TEMPLATES[3].note, confirmed: false });
    channels.push({ channel: "the hosting provider, once the address's own records name one", basis: ABUSE_TEMPLATES[3].note, confirmed: false, requires: "a lookup, or a person reading the RDAP record" });
  }
  return { target: route.target, kind: route.kind, channels, confirmed_none: channels.length === 0 };
}

/* ------------------------------------------------------------------ the report outline */

/**
 * The skeleton a report is written into. It carries the two sections most reports omit, and it names
 * its own sharing scope in the document rather than in the message that carries it.
 */
export function reportOutline(targets, { tlp = "TLP:AMBER", audience = "the operators named below" } = {}) {
  const level = TLP_LEVELS.find((l) => l.level === tlp) ? tlp : "TLP:AMBER";
  const permits = TLP_LEVELS.find((l) => l.level === level).permits;
  return {
    tlp: level,
    tlp_permits: permits,
    audience,
    sections: [
      { heading: "What was observed", body: "the records quoted, each with the URL or file it came from and the time it was read" },
      { heading: "What the observer did", body: "the actions taken that produced the observations, so a reader can repeat them" },
      { heading: "What this report does NOT claim", body: NOT_CLAIMABLE },
      { heading: "What is asked for", body: "one specific action per recipient, with the record that supports it" },
      { heading: "Sharing scope", body: `${level}: ${permits}` },
    ],
    targets: targets.map((t) => String(t)),
    rules_version: ATTRIBUTION_RULES_VERSION,
  };
}

/* ------------------------------------------------------------------ findings */

const LAYER = "metadata";

/**
 * The findings a report can carry. Ids match the catalog entries, so every emitted id is one the
 * catalog declares -- the same rule every other tool in this project follows.
 */
export function attributionFindings(targets) {
  const out = [];
  const add = (severity, id, title, detail, evidence) => out.push({ layer: LAYER, severity, id, title, detail, evidence });
  for (const raw of Array.isArray(targets) ? targets : []) {
    const route = routeFor(raw);
    const channels = abuseChannelsFor(raw);
    if (route.kind === "unknown" || route.kind === "empty") {
      add("info", "attribution-target-kind-unknown",
        `The shape of ${JSON.stringify(String(raw))} is not one a registry route can be built for`,
        "A person can say what the target is; this tool cannot infer it from the string, and guessing would produce a report about something else.",
        { target: String(raw), kind: route.kind });
      continue;
    }
    if (route.undetermined) {
      add("info", "attribution-tld-not-in-table",
        `No RDAP base is recorded here for ${route.registrable ? "." + route.registrable.split(".").pop() : route.target}`,
        "The bootstrap table in this file covers the TLDs it lists and no others. The authoritative list is the IANA bootstrap file, and the report names it rather than pretending to know.",
        { target: route.target, undetermined: route.undetermined });
    }
    // There was a `confirmed_none` branch here, reporting targets for which no channel can be
    // derived. It was unreachable: the unknown-kind branch above returns for every target that yields
    // no channels, so the case had already been taken. The channel gap is still reported -- by the
    // catalog entry and by the target-kind finding -- and an unreachable branch is worse than a
    // missing one, because it reads as a case somebody thought about.
  }
  return out;
}

/* ------------------------------------------------------------------ the lookup, when allowed */

/**
 * The commands that perform the lookup, for a person to run.
 *
 * This is the shape this project uses everywhere it cannot reach something itself: it hands over the
 * command that answers the question and says plainly that it did not run it. Both shells on this
 * machine get one, because a reference command that only works in the shell the author happened to
 * use is a reference command for the author.
 */
export function registryQueryCommand(raw) {
  const route = routeFor(raw);
  if (!route.rdap_url) {
    return { target: route.target, kind: route.kind, commands: [], note: "no registry route exists for this target's shape, so there is nothing to query" };
  }
  const curl = `curl -sS -H "Accept: application/rdap+json" "${route.rdap_url}"`;
  const pwsh = `Invoke-RestMethod -Headers @{ Accept = 'application/rdap+json' } -Uri '${route.rdap_url}' | ConvertTo-Json -Depth 8`;
  return {
    target: route.target,
    kind: route.kind,
    url: route.rdap_url,
    commands: [
      { shell: "bash", command: curl },
      { shell: "pwsh", command: pwsh },
    ],
    whois: route.whois_reference,
    note: "This tool did not run either command. Running one reaches the registry for this target, which is a network action the caller decides on -- not a side effect of asking for a report.",
  };
}

/**
 * One RDAP query, over HTTPS. The fetcher is REQUIRED and this module imports no transport, so the
 * only way this runs is if the caller brought one, which the tool above deliberately does not.
 *
 * The fetcher is injected for two more reasons: the suite drives every branch without a network, and
 * nothing here retries aggressively. A registry that rate-limits is a registry that rate-limits, and
 * a tool that hammers one on someone else's behalf has made the observer part of the problem.
 */
export async function lookupTarget(raw, { fetcher, timeoutMs = 15000 } = {}) {
  const route = routeFor(raw);
  if (!route.rdap_url) {
    return { target: route.target, kind: route.kind, attempted: false, reason: "no RDAP route for this target's shape" };
  }
  if (typeof fetcher !== "function") {
    return { target: route.target, kind: route.kind, attempted: false, reason: "no transport was provided, and this module imports none" };
  }
  const asked_at = new Date().toISOString();
  try {
    const res = await fetcher(route.rdap_url, { timeoutMs });
    const json = res && res.json ? res.json : null;
    const entities = Array.isArray(json?.entities) ? json.entities : [];
    const abuse = [];
    const walk = (list) => {
      for (const e of list) {
        const roles = Array.isArray(e?.roles) ? e.roles : [];
        const isAbuse = roles.includes("abuse");
        const vcard = Array.isArray(e?.vcardArray?.[1]) ? e.vcardArray[1] : [];
        const emails = vcard.filter((v) => Array.isArray(v) && v[0] === "email").map((v) => v[3]).filter((v) => typeof v === "string");
        if (isAbuse || emails.length) {
          abuse.push({ handle: e?.handle ?? null, roles, emails, from_abuse_role: isAbuse });
        }
        if (Array.isArray(e?.entities)) walk(e.entities);
      }
    };
    walk(entities);
    return {
      target: route.target,
      kind: route.kind,
      attempted: true,
      url: route.rdap_url,
      asked_at,
      via: res?.via ?? null,
      ok: true,
      registry_handle: json?.handle ?? null,
      status: Array.isArray(json?.status) ? json.status : [],
      events: Array.isArray(json?.events) ? json.events.map((e) => ({ action: e?.eventAction ?? null, date: e?.eventDate ?? null })) : [],
      nameservers: Array.isArray(json?.nameservers) ? json.nameservers.map((n) => n?.ldhName ?? null).filter(Boolean) : [],
      abuse_contacts: abuse,
      grade: abuse.length ? "registry-record" : "unattributable",
      grade_note: abuse.length
        ? "the registry's own record names these contacts; whether they act is not something the record says"
        : "the record was read and names no abuse contact, so no operator is named by it",
    };
  } catch (err) {
    return {
      target: route.target,
      kind: route.kind,
      attempted: true,
      url: route.rdap_url,
      asked_at,
      ok: false,
      error: err && err.message ? err.message : String(err),
      grade: "unattributable",
      grade_note: "the query failed, which says nothing about the target",
    };
  }
}

/** The whole report: routes, channels, commands, outline, findings, and lookups only if a transport came. */
export async function attributionReport(targets, { allowLookup = false, fetcher = null, tlp = "TLP:AMBER" } = {}) {
  const list = (Array.isArray(targets) ? targets : []).map((t) => String(t));
  const routes = list.map((t) => routeFor(t));
  const channels = list.map((t) => abuseChannelsFor(t));
  const commands = list.map((t) => registryQueryCommand(t));
  const lookups = [];
  if (allowLookup && typeof fetcher === "function") {
    for (const t of list) lookups.push(await lookupTarget(t, { fetcher }));
  }
  return {
    schema: ATTRIBUTION_SCHEMA,
    rules_version: ATTRIBUTION_RULES_VERSION,
    targets: list,
    routes,
    channels,
    commands,
    lookups,
    lookup_allowed: allowLookup === true,
    lookup_transport: typeof fetcher === "function" ? "provided by the caller" : "none: this module imports no transport",
    report: reportOutline(list, { tlp }),
    evidence_grades: EVIDENCE_GRADES,
    not_claimable: NOT_CLAIMABLE,
    bootstrap: { as_of: RDAP_BOOTSTRAP.as_of, authoritative: RDAP_BOOTSTRAP.authoritative, redirector: RDAP_BOOTSTRAP.redirector, tlds: Object.keys(RDAP_BOOTSTRAP.tlds).length },
  };
}
