#!/usr/bin/env node
/**
 * Attribution suite -- drives lib/attribution.mjs and the three catalog entries behind
 * aikawamei_attribution.
 *
 * What this suite is really guarding
 * ----------------------------------
 *   1. THE DEFAULT HAS TO STAY OFF THE NETWORK. Every assertion about routes and channels runs with
 *      an injected fetcher that THROWS if it is called. That is the difference between "does not
 *      reach the network" as a property and as a promise: with the switch off, a single accidental
 *      call fails the suite loudly instead of quietly sending a query on the user's behalf.
 *
 *   2. THE GRADES MUST NAME SOURCES, NOT WEIGHTS. The tempting failure here is a vocabulary that
 *      drifts into "likely" and "probable", which reads as an attribution without being one. The
 *      suite asserts the closed set of grade ids, so adding a probability word is a deliberate edit.
 *
 *   3. THE REPORT HAS TO CARRY WHAT IT DOES NOT CLAIM. Both sections are asserted for presence and
 *      for content, because their absence reads as confidence -- the failure mode is silent.
 *
 *   4. A LOOKUP THAT FAILS IS NOT AN ANSWER ABOUT THE TARGET. A network error, a 404 and a
 *      rate-limit all mean the record was not read; the suite asserts that all three come back as
 *      unattributable rather than as an absence of abuse contacts.
 *
 * Division of labour: checks.mjs owns the catalog, selftest owns the tool surface. This suite owns
 *   the attribution target: its tables, its routes, its off-by-default network, and its refusals.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const attribution = await import(pathToFileURL(path.join(root, "lib", "attribution.mjs")).href);
const {
  ATTRIBUTION_SCHEMA, ATTRIBUTION_RULES_VERSION, RDAP_BOOTSTRAP,
  EVIDENCE_GRADES, TLP_LEVELS, NOT_CLAIMABLE,
  classifyTargetKind, registrableDomain, routeFor, abuseChannelsFor,
  reportOutline, attributionFindings, lookupTarget, attributionReport,
} = attribution;
const checks = await import(pathToFileURL(path.join(root, "lib", "checks.mjs")).href);
const { CHECK_CATALOG, TARGETS } = checks;

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/** A fetcher that fails the suite if anything calls it: the network is off unless a test says so. */
const forbiddenFetcher = async (url) => { throw new Error(`the network was reached with the switch off: ${url}`); };

/* ================================================== classification */

section("what kind of target this is, from its shape only");

check("a domain", classifyTargetKind("example.com") === "domain");
check("a subdomain is still a domain", classifyTargetKind("a.b.example.com") === "domain");
check("an IPv4 address", classifyTargetKind("192.0.2.10") === "ipv4");
check("an octet out of range is NOT an address", classifyTargetKind("300.1.1.1") === "unknown");
check("an IPv6 address", classifyTargetKind("2001:db8::1") === "ipv6");
check("an ASN, in lower case", classifyTargetKind("as15169") === "asn");
check("an email", classifyTargetKind("abuse@example.org") === "email");
check("a bare word is unknown rather than guessed at", classifyTargetKind("maybe-a-host") === "unknown");
check("an empty string is its own kind", classifyTargetKind("   ") === "empty");

check("the registrable domain of a two-label name is itself",
  registrableDomain("example.com") === "example.com");
check("a three-label name reduces to two when the TLD is a known one",
  registrableDomain("mail.example.com") === "example.com");
check("a trailing dot is tolerated", registrableDomain("example.com.") === "example.com");

/* ================================================== routing */

section("routes: the table answers, and says when it cannot");

const comRoute = routeFor("example.com");
check("a TLD in the table routes to the registry's own service",
  comRoute.rdap_url === "https://rdap.verisign.com/com/v1/domain/example.com", comRoute.rdap_url);
check("and the answer names where the table came from",
  typeof comRoute.rdap_source === "string" && comRoute.rdap_source.includes(RDAP_BOOTSTRAP.as_of), comRoute.rdap_source);
check("nothing about that route is undetermined", comRoute.undetermined === null);

const oddRoute = routeFor("example.zz");
check("a TLD outside the table falls back to the redirector",
  oddRoute.rdap_url === `${RDAP_BOOTSTRAP.redirector}/domain/example.zz`, oddRoute.rdap_url);
check("and it says so, naming the authoritative file",
  oddRoute.undetermined !== null && oddRoute.undetermined.answered_by === RDAP_BOOTSTRAP.authoritative,
  JSON.stringify(oddRoute.undetermined));

check("an address routes through the redirector, which knows the RIR",
  routeFor("192.0.2.10").rdap_url === `${RDAP_BOOTSTRAP.redirector}/ip/192.0.2.10`);
check("an ASN routes the same way, without the prefix",
  routeFor("AS15169").rdap_url === `${RDAP_BOOTSTRAP.redirector}/autnum/15169`, routeFor("AS15169").rdap_url);
check("an email routes on its domain", routeFor("abuse@example.com").rdap_url.endsWith("/domain/example.com"));
check("a whois server is offered as a reference, never as a capability",
  routeFor("example.com").whois_reference.server === "whois.iana.org"
  && /does not speak whois/.test(routeFor("example.com").whois_reference.note));
check("an unrecognisable target has no route and says why",
  routeFor("!!!").undetermined !== null && routeFor("!!!").rdap_url === null);

/* ================================================== channels, as candidates */

section("abuse channels: candidates, labelled as candidates");

const domainChannels = abuseChannelsFor("example.com");
check("a domain yields channels", domainChannels.channels.length >= 3, String(domainChannels.channels.length));
check("every channel is marked unconfirmed", domainChannels.channels.every((c) => c.confirmed === false));
check("the convention is named as a convention",
  domainChannels.channels.some((c) => c.channel === "abuse@example.com" && /convention/.test(c.basis)));
check("the registrar is offered, because that is who can suspend a domain",
  domainChannels.channels.some((c) => /registrar/.test(c.channel)));
check("no channel claims to have been verified", !/verified/.test(JSON.stringify(domainChannels.channels)));

const ipChannels = abuseChannelsFor("192.0.2.10");
check("an address yields the RIR channel", ipChannels.channels.some((c) => /RIR/.test(c.channel)));
check("and the hosting channel says what it depends on",
  ipChannels.channels.some((c) => c.requires === "a lookup, or a person reading the RDAP record"));
check("an unrecognisable target yields no channels at all",
  abuseChannelsFor("!!!").confirmed_none === true && abuseChannelsFor("!!!").channels.length === 0);

/* ================================================== the report outline */

section("the report outline, and the two sections reports usually omit");

const outline = reportOutline(["example.com"], { tlp: "TLP:GREEN" });
check("the outline carries the level it was written for", outline.tlp === "TLP:GREEN");
check("and carries what that level permits", outline.tlp_permits === TLP_LEVELS.find((l) => l.level === "TLP:GREEN").permits);
check("an unknown level falls back rather than travelling unmarked",
  reportOutline(["x.com"], { tlp: "TLP:PURPLE" }).tlp === "TLP:AMBER");
check("a section lists what the report does not claim",
  outline.sections.some((s) => /does NOT claim/.test(s.heading) && Array.isArray(s.body) && s.body.length >= 4));
check("and a sharing-scope section names the level",
  outline.sections.some((s) => /Sharing scope/.test(s.heading) && s.body.includes("TLP:GREEN")));
check("every section says what to put in it rather than leaving a blank heading",
  outline.sections.every((s) => (typeof s.body === "string" && s.body.length > 10) || (Array.isArray(s.body) && s.body.length > 0)));

/* ================================================== grades name sources */

section("evidence grades name sources, not weights");

const gradeIds = EVIDENCE_GRADES.map((g) => g.grade);
check("the grade set is the closed one",
  JSON.stringify(gradeIds) === JSON.stringify(["registry-record", "self-declared", "dns-answer", "third-party-report", "unattributable"]),
  gradeIds.join(","));
check("no grade is a probability word",
  !gradeIds.some((g) => /likely|probable|possible|suspected/.test(g)), gradeIds.join(","));
check("unattributable is a grade, not an error",
  gradeIds.includes("unattributable"));
check("every grade says where a reader can obtain it",
  EVIDENCE_GRADES.every((g) => typeof g.holder === "string" && g.holder.length > 10));
check("the not-claimable list refuses motive, identity and correlation",
  NOT_CLAIMABLE.some((l) => /person, group or organisation/.test(l))
  && NOT_CLAIMABLE.some((l) => /motive/.test(l))
  && NOT_CLAIMABLE.some((l) => /close together in time/.test(l)));

/* ================================================== the network is off unless asked */

section("the network, off by default and asserted by a fetcher that throws");

const offReport = await attributionReport(["example.com", "192.0.2.10"], { fetcher: forbiddenFetcher });
check("with the switch off, no lookup is performed at all",
  offReport.lookups.length === 0 && offReport.lookup_allowed === false);
check("and the report still answers the three questions",
  offReport.routes.length === 2 && offReport.channels.length === 2 && offReport.report.tlp === "TLP:AMBER");

const onReport = await attributionReport(["example.com"], {
  allowLookup: true,
  fetcher: async (url) => ({
    json: {
      handle: "EXAMPLE-COM",
      status: ["client transfer prohibited"],
      events: [{ eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" }],
      nameservers: [{ ldhName: "A.IANA-SERVERS.NET" }],
      entities: [
        { handle: "REG", roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Registrar"], ["email", {}, "text", "support@registrar.example"]]] },
        { handle: "ABU", roles: ["abuse"], vcardArray: ["vcard", [["email", {}, "text", "abuse@registrar.example"]]] },
      ],
    },
    via: "direct",
  }),
});
check("with the switch on, the lookup is recorded rather than implied",
  onReport.lookups.length === 1 && onReport.lookups[0].attempted === true && typeof onReport.lookups[0].asked_at === "string");
check("the registry record's own handle and status come back",
  onReport.lookups[0].registry_handle === "EXAMPLE-COM" && onReport.lookups[0].status.length === 1);
check("abuse contacts are extracted, with the abuse role marked",
  onReport.lookups[0].abuse_contacts.length === 2
  && onReport.lookups[0].abuse_contacts.some((c) => c.from_abuse_role === true), JSON.stringify(onReport.lookups[0].abuse_contacts));
check("a record with contacts is graded registry-record",
  onReport.lookups[0].grade === "registry-record" && /whether they act/.test(onReport.lookups[0].grade_note));

/* ================================================== a failed lookup is not an answer */

section("a lookup that fails says nothing about the target");

const notFound = await lookupTarget("example.com", { fetcher: async () => { throw new Error("HTTP 404 Not Found"); } });
check("a 404 comes back as a failure, not as an empty record", notFound.ok === false && notFound.grade === "unattributable");
check("and the note says the query failed rather than the target being clean",
  /says nothing about the target/.test(notFound.grade_note), notFound.grade_note);

const rateLimited = await lookupTarget("example.com", { fetcher: async () => { throw new Error("HTTP 429 Too Many Requests"); } });
check("a rate limit is also unattributable", rateLimited.grade === "unattributable");

const emptyRecord = await lookupTarget("example.com", { fetcher: async () => ({ json: { handle: "X", entities: [] } }) });
check("a record that was read and names no abuse contact is unattributable too",
  emptyRecord.ok === true && emptyRecord.grade === "unattributable" && /names no abuse contact/.test(emptyRecord.grade_note));

const noRoute = await lookupTarget("!!!", { fetcher: forbiddenFetcher });
check("a target with no route is not looked up at all", noRoute.attempted === false);

/* ================================================== findings belong to the catalog */

section("findings are catalog entries, not a parallel vocabulary");

const findings = attributionFindings(["example.com", "!!!", "example.zz", "192.0.2.10"]);
const ids = findings.map((f) => f.id);
check("an unrecognisable target produces the unknown-kind finding", ids.includes("attribution-target-kind-unknown"), ids.join(","));
check("a TLD outside the table produces the unmapped finding", ids.includes("attribution-tld-not-in-table"), ids.join(","));
check("a plain address produces neither", !ids.includes("attribution-no-abuse-channel"), ids.join(","));
check("every id emitted appears in the catalog",
  ids.every((id) => CHECK_CATALOG.some((c) => c.id === id)), ids.join(","));
check("every emission carries evidence, so a fact slot has something to hold",
  findings.every((f) => f.evidence !== undefined));
check("attribution is a declared target", TARGETS.includes("attribution"));
check("the catalog declares the attribution entries",
  CHECK_CATALOG.filter((c) => c.targets.includes("attribution")).length === 3);

/* ================================================== it sends nothing, structurally */

section("it sends nothing and attributes no one, asserted on the source");

const src = fs.readFileSync(path.join(root, "lib", "attribution.mjs"), "utf8");
const senders = ["smtp", "mailto:", "nodemailer", "form-data", "multipart/form-data", "child_process", "execFile", "spawnSync"];
const foundSenders = senders.filter((s) => src.includes(s));
check("no mail, form or process API appears in the module",
  foundSenders.length === 0, JSON.stringify(foundSenders));
check("the module does not call fetch itself, only the injected transport",
  !/fetch\(/.test(src));
check("the module imports NO transport at all, so the tool layer decides the boundary",
  !/node:https|node:net|node:dgram|node:tls/.test(src) && !/from "\.\/net\.mjs"/.test(src));
check("a lookup without a transport refuses rather than inventing one",
  (await lookupTarget("example.com", {})).attempted === false);
check("no attribution verb appears: the vocabulary has no place to put a culprit",
  !/\b(attributed to|culprit|suspect|perpetrator)\b/i.test(src));
check("the schema string is stable for a reader that keys on it",
  ATTRIBUTION_SCHEMA === "aikawamei-attribution/1" && ATTRIBUTION_RULES_VERSION === "1");

/* ================================================== summary */

console.log(`\n  passed ${pass} / ${pass + fail}`);
if (fail) {
  console.log("\n  failures:");
  for (const f of failures) console.log(`    ${f}`);
  process.exit(1);
}
