# AikawaMei

[![release](https://github.com/Nesarf/AikawaMei/actions/workflows/release.yml/badge.svg)](https://github.com/Nesarf/AikawaMei/actions/workflows/release.yml)

**A portable static posture auditor for Tor Browser and Firefox.**

One pure-Node head (`lib/core.mjs`), two interfaces (MCP stdio server + CLI), sharing the same single `TOOLS[].execute` -- no second implementation.

> *AikawaMei* -- the uninvited deity, a wrathful god. It does not fight for you; it only points out, one item at a time, the traces already left on your machine.
> The name is about "being visible": **an auditor does not create safety, it merely leaves residue nowhere to hide.**

---

## 1. What it is, and what it is **not**

This section has to come first. **This tool is designed to say "no".**

### What it does

| Layer | What is audited |
|---|---|
| **Build layer** | Tor Browser: version, channel, Firefox base, bundled Tor version. Firefox: application version, and the version the profile was last used with |
| **Transport layer** | Tor: bridge configuration, pluggable transport inventory, **uTLS fingerprint mimicry**, **domain fronting**, built-in vs. custom bridges, deprecated PTs, Quick Start timing. Firefox: proxy mode, DNS over HTTPS, content blocking, fingerprint resistance, cookie policy |
| **Content/authorization layer** | Tor: onion service client authorization, whether `.onion` service private keys exist. Firefox: saved-login database, key material, client certificate store |
| **Metadata layer** | Tor: the **guard set** in `state`, descriptor cache, PT state, profile first-use time, session checkpoints, browsing history. Firefox: history and cookies, per-site permissions, form history, site storage, telemetry client ID, account linkage, extensions |
| **Endpoint layer** | Where the install or profile lives, user/temp directory residue, how many profiles exist, persistent vs. amnesic, and whether the volume holding it is encrypted at rest (to the extent a static, unprivileged audit can tell -- see `disk-encryption` in `aikawamei_checks`) |

Two questions sit **outside** an audit, and both are served by looking at the surface rather
than at your machine:

- **What can this tool even see?** `aikawamei_checks` prints the declared check surface, one
  entry per check, each stating what it reads and what it explicitly does not cover.
- **What would travel with this directory?** `aikawamei_handoff` scans a folder you are about to
  give someone else and reports the key-shaped names, residue and build artefacts that would go
  with it -- by name only, never by reading contents, and it says so where it reports.
- **Did anything move?** `aikawamei_baseline` captures the audit as a set of per-check
  fingerprints and diffs a later run against it. Posture at rest and posture *drift* are
  different questions, and only the second one catches a guard set quietly growing.
- **What did the automation leave behind?** `aikawamei_sessions` reports the session material the
  browser-automation toolchains persist -- plaintext storage states, cookie jars, HTTP archives,
  profile stores and profile directories -- and says which of them sit inside a git working tree.
  None of the five frameworks reports this, and the file that turns a copy of a folder into a
  live account is written by all of them.

- **Is there a foothold on this machine, and where?** `aikawamei_triage` reads five artefact
  surfaces that are files -- WER crash reports, Prefetch, the Startup folders, scheduled-task XML,
  and executables under the locations anything can write to -- aligns them in time, and reports the
  windows where several mechanisms agree. The registry surfaces it cannot reach without running a
  program are listed with the command that answers each.
- **Collect it before it is gone.** `aikawamei_collect` copies what a triage run found, most
  perishable first, hashing each copy and writing a manifest that is a hash chain.
- **Has this installation been changed?** `aikawamei_self` compares the tool's own files against a
  manifest you kept, verifies a record chain against the length and head a receipt reported, signs a
  manifest so someone else can check it, and can refuse to start when the installation does not match.

**Read-only by default, and it says which tools can write.** Nothing here starts Tor, touches
configuration or moves anything. Four tools write **only when asked to**: `aikawamei_sessions` and
`aikawamei_triage` append a record when you name a chain, `aikawamei_collect` copies files to a
destination you name, and `aikawamei_self` keeps a manifest where you name. With none of those
arguments, nothing is written. The only network action is the version check, which is off unless it
is asked for.

### What it does **not** do

Every tool, on every path -- error paths included -- carries this notice. Its **first line is composed
from what the tool declares**, so it is not the same sentence everywhere, and the three lines after it
are identical wherever they appear:

```
aikawamei_env, aikawamei_audit, ... (a tool that only reads)
This tool reads files and never launches the application under audit, and never touches the network.
It does NOT address: traffic correlation and timing analysis, endpoint compromise
(malware / device seizure), or anything that happens after decryption.
It protects what is visible without running anything: configuration posture, the residue software
and sessions leave behind, and the artefacts that record a foothold. It is NOT an anti-tracking tool.
A clean audit is NOT proof of safety. Treating it as one is a misuse.

aikawamei_collect (a tool that also writes)
This tool reads files and never launches the application under audit, writes files at paths you name
when you ask it to, and never modifies or moves what it reads, and never touches the network.
It does NOT address: ... (the same three lines)
```

The first line names **every class the tool declares** rather than the strongest one, because two of
the classes are not comparable: a tool that copies files and a tool that asks a public endpoint are
both described, and a notice that mentioned only one of them would be true by omission -- the one
shape of false this project treats as worse than saying nothing. `aikawamei_version` is the only tool
whose notice carries a network clause other than "never touches the network".

The rest of this section is this README explaining that notice, not repeating it.

- **Traffic correlation and timing analysis**: an adversary does not need to read the content, only to line up the entry and exit timings. **Content encryption helps the metadata layer by roughly zero.**
- **Live protocol queries and reachability tests**: refused rather than merely absent, and the two are refused for different reasons. Querying Tor's ControlPort is refused because an audit that depends on whether a service happens to be running stops being deterministic, and determinism is what the baseline and drift feature rests on. Testing whether a configured bridge is reachable is refused because **the check would be the harm**: dialing a bridge from your address, at a moment of your choosing, manufactures exactly the metadata an adversary needs to find and fingerprint that bridge's use. See discipline 18.
- **Endpoint compromise**: malware, keyloggers, a seized device. Cryptography cannot reach this layer.
- **What happens after decryption**: the recipient read it, kept a copy, said something, met someone -- the most common point of failure in public cases.
- **People**: no technical solution exists. This is the one layer `aikawamei_layer_assess` will not recommend anything for, and the one `aikawamei_audit` never reports a finding under.

> A clean audit is not a licence to relax. To address the metadata layer, the direction that
> works is a mixnet (Nym) or a metadata-hiding messenger (SimpleX / Cwtch) -- not more
> configuration piled onto Tor. That advice is this document's, not the tool's.

### The emblem

`AikawaMei` -- the bare name, no extension, at the repository root and inside every package -- is
a sealed statement about the work it is sealed to. It is a short ASCII envelope
holding an AES-256-GCM seal over a few lines of text about that work: title, artist, album,
duration, format, and two digests.

The single-file executable has no files beside it to read, so the seal is also inlined into the
bundle at build time. The file is the copy a person can find and read the shape of; the inline is
what the executable reports from. Both paths are exercised -- the suite passes an inlined value
to the loader, and the bundle is run from a directory with no seal in it before it is shipped.

The key is derived from the work's own content digest, so **the seal opens only where the work
itself is present**. That is the whole of it, and it is worth being exact about what that does
and does not mean:

- It is **not** a secret, a credential, or a security control, and nothing here depends on it
  for safety. Anyone holding the source work can derive the key; the repository alone cannot.
- What GCM adds is **tamper-evidence**: an altered seal fails to open rather than opening to
  something else. The suite asserts exactly that, along with a wrong source, an altered
  nonce, an altered tag, and a swapped payload.
- No audio is carried in the repository or in any package, and the project distributes none.
  The default target is Tor Browser and the emblem belongs to a piece of music; a project
  about what you leave behind should not be the thing that leaves a copy.

`aikawamei_env` reports it as `emblem`, in structure only -- `present`, `sealed`, `format`,
`cipher`, `kdf`, `opens_with`. It never reports contents, because it holds no key. Sealing is
done by `packaging/emblem.mjs`, which reads the work, derives the text from the work's own
metadata rather than from the machine or the moment, and writes the envelope:

```
node packaging/emblem.mjs seal <source-work>    # writes AikawaMei
node packaging/emblem.mjs open <source-work>    # prints the statement
node packaging/emblem.mjs verify                # structure only, no key needed
```

---

## 2. Why a tool, not a document

Wrap an analysis in a plugin and the plugin only returns an essay -- but a reader can already read an essay, which is zero gain.

So this carries only the two **executable** pieces:

1. **Posture audit** -- static, reproducible, with concrete artifacts (which file, how large, how long ago it was written)
2. **Layer arbitration** -- `aikawamei_layer_assess` encodes "which layer's problem calls for which layer's countermeasure" as a program. Its core capability is **recognizing layer mismatch and raising an alarm**: real-time round trips and metadata protection are in hard conflict; pure content sensitivity should not be wrapped in high-risk tradecraft.

Point 2 matters especially: an advisor that only dispenses advice manufactures false confidence. This tool's `does_not_cover` field is **permanent**, not an optional decoration.

---

## 3. Installation

### Dependencies

```bash
npm install          # only @modelcontextprotocol/sdk
```

Node >= 18 (`fetch` and WebCrypto are required). Zero other runtime dependencies -- the proxy tunnel is implemented from the stdlib.

### Prebuilt packages

**The Windows artifacts are Authenticode-signed, with a self-signed certificate.** `aikawamei.exe`,
its two target variants and the three MSIs carry a signature from `O=S.M.Y.T., CN=S.M.Y.T. Code
Signing`, timestamped by a public authority. What that signature is worth is worth stating rather than
implying: it proves the file is the one that was signed and has not changed since, and it names the
publisher **within that certificate**. It does not establish identity to a public certification
authority, because there is none -- so Windows will still warn unless the certificate itself is trusted
on the machine reading it. A self-signed installer that says it is self-signed is more useful than one
whose origin the reader has to guess.

Every artifact is produced **per target**, so a download can carry a default. `AIKAWAMEI_TARGET`
selects that default; an explicit `--target` argument always overrides it, which is what keeps a
target-specific build from becoming a target-*locked* one.

| Form | Runtime it needs | Verified by |
|---|---|---|
| Portable `.zip` + `.cmd` launchers | **Node.js >= 18 on the host** | Extracted, all six launchers run from a foreign working directory |
| `.msi` (WiX, perMachine, x64) | **Node.js >= 18 on the host** | `msiexec /i /qn` real install as an administrator: payload under `Program Files`, a registration the 64-bit registry view can see, the `bin` directory on the machine `PATH`, the launcher then run **by name from that PATH** and answering with the schema it should, and `msiexec /x /qn` leaving the machine unmodified -- the `PATH` is compared against a snapshot taken before the install rather than eyeballed. The installer's own images are checked by reading them back out of the built package |
| Single-file `.exe` (Node SEA) | **nothing** | Run with Node removed from `PATH`; CLI and `--mcp` both answer |
| `winget` manifests | (installs the MSI, so Node) | `winget validate` 3/3, recorded SHA matches the MSI it was generated from |
| `npm` package | **Node.js >= 18** | `npm pack`, global install into a scratch prefix, both commands run |
| Linux `.tar.gz` + `install.sh` | **Node.js >= 18 on the host** | `./install.sh` executed for real, six wrappers installed, target pinning and `--uninstall` checked |
| `.deb` | `nodejs (>= 18)` | `dpkg-deb` accepted it, then `dpkg -i` and run |
| `.rpm` | `nodejs >= 18` | `rpm -i` and run; `Conflicts` refuses a second variant correctly |
| AppImage | **nothing** | Run on a distribution with no node and no `libnode`; CLI and `--mcp` both answer |
| Flatpak | **nothing** | `flatpak install` and `run`; the bundled interpreter reports its version while `command -v node` finds nothing |
| Snap (classic) | **nothing** | `snap install --classic` and `run`; same check as the Flatpak |

Four forms carry their own runtime and the rest use the host's, and the difference is worth
knowing before picking one. Carrying a runtime costs size: the Linux tarball is ~170 KB, the
MSI ~1.1 MB, and the self-contained ones are 16 MB (Flatpak) to 40 MB (AppImage) to 90 MB (the
single-file executable). A runtime that works anywhere cannot share libraries with the machine
that built it. That is not a theoretical distinction: the AppImage used to copy the `node` that
happened to be on `PATH`, which on a distribution that ships node as a shared library produced
an artifact that only ran on machines with that library.

The MSI is the outlier among the host-runtime forms, and it is worth knowing why it is five times
the size of the tarball that carries the same code: 216 KB without an installer UI, 1140 KB with
one. Of that increase, 535 KB is the two dialog images and 389 KB is the dialog set and its
custom-action library. A wizard is not free, and an MSI is not automatically the small option.
`packaging/linux/fetch-node.sh` fetches the official self-contained build, pinned to a version
and checked against its published SHA256, and both the AppImage and the snap use it.

`confinement` for the snap is `classic`, which asks the user to opt in with `--classic`. The
alternative was measured rather than assumed: under strict confinement the `home` interface
excludes hidden files, so `~/.mozilla` is unreachable and the Firefox target cannot work at
all. A strict snap would install cleanly and then be unable to do the one thing it exists for.

Build them yourself with the scripts in `packaging/` -- each one stages a bundle and then wraps
it, so no form re-implements the tool. `-Target all` means the neutral package that auto-detects
at runtime, in every one of them; the pinned `-tor` and `-firefox` variants are separate calls.

```powershell
pwsh packaging/pack-portable.ps1       -Target firefox
pwsh packaging/pack-msi.ps1            -Target tor
pwsh packaging/pack-sea.ps1            -Target firefox
pwsh packaging/linux/build-tarball.ps1 -Target firefox
pwsh packaging/linux/build-deb.ps1     -Target firefox
```

### MCP setup

AikawaMei speaks MCP over stdio, so any MCP-capable client can run it: point the client at
`mcp/index.mjs` and it will discover the four tools.

```json
{
  "mcpServers": {
    "AikawaMei": {
      "command": "node",
      "args": ["/path/to/AikawaMei/mcp/index.mjs"]
    }
  }
}
```

If the client registers servers through a CLI, the equivalent is:

```bash
<client> mcp add AikawaMei -- node /path/to/AikawaMei/mcp/index.mjs
```

Installing from npm also exports the server as `aikawamei-mcp`, so the command can simply be
`aikawamei-mcp`.

### CLI

```bash
node cli/index.mjs                       # usage and tool list
node cli/index.mjs aikawamei_env --human
node cli/index.mjs aikawamei_audit --human
node cli/index.mjs aikawamei_audit --target firefox --human
node cli/index.mjs aikawamei_audit --layer metadata --min_severity warn --human
node cli/index.mjs aikawamei_version --human
node cli/index.mjs aikawamei_checks --target tor --layer endpoint --human
node cli/index.mjs aikawamei_baseline > baseline.json
node cli/index.mjs aikawamei_baseline --mode diff --baseline_path baseline.json --human
node cli/index.mjs aikawamei_layer_assess --metadata_sensitive true --realtime true --human
```

Output is JSON by default (easy for a program to consume); `--human` switches to a human-readable layout.

---

## 4. Tool reference

Every tool takes an optional `target` (`auto` | `tor` | `firefox`), where `auto` prefers Tor
Browser and falls back to Firefox. `AIKAWAMEI_TARGET` sets the same default from the environment,
which is how the per-target packages pin one without forking the code; an explicit argument
always wins over both.

Note that **two different layer taxonomies** appear in this document and they are not the same
thing. The audit tags each finding with one of six layers -- `build`, `transport`, `crypto`
(shown as "Content / authorization"), `metadata`, `endpoint`, `social` -- and `aikawamei_audit`'s
`layer` parameter accepts the first five, because nothing is ever reported under `social`: there
is no technical solution to it, so there is nothing to find. Section 5 describes the separate
four-layer *model* that `aikawamei_layer_assess` reasons over.

### `aikawamei_env`
Probes the runtime environment and discovers every supported target: Tor Browser installs under `targets.tor`, Firefox profiles under `targets.firefox`. **Run this first to get a path for the other tools.**

| Parameter | Description |
|---|---|
| `install` | Optional: a Tor Browser install root to use directly instead of auto-discovery |

The response also carries `emblem`, the structure of the seal described in [The emblem](#the-emblem). It reports shape and never contents: this process holds no key.

### `aikawamei_audit`
The full static audit.

| Parameter | Description |
|---|---|
| `target` | `auto` \| `tor` \| `firefox` |
| `install` | Tor Browser install root; **when given explicitly, only that one location is audited**, otherwise auto-discovery |
| `profile` | Firefox profile directory; defaults to the profile the application opens, else the first found |
| `layer` | `all` \| `build` \| `transport` \| `crypto` \| `metadata` \| `endpoint` |
| `min_severity` | `ok` \| `info` \| `warn` \| `critical`; **default `ok` (everything shown, including positive findings)** |

Returns `findings` grouped by layer, each carrying `layer / severity / id / title / detail / evidence`.

### `aikawamei_version`
Checks the version in use against the vendor's own published metadata, and reports how far behind
it is. Both targets are supported:

| Target | Local version read from | Compared against |
|---|---|---|
| `tor` | `tbb_version.json` in the install | the Tor Project release endpoint (`aus1.torproject.org`), per channel |
| `firefox` | `application.ini` in the program directory, else the profile's `compatibility.ini` | `product-details.mozilla.org/1.0/firefox_versions.json` |

A local version can honestly be absent -- a machine may have neither installed -- in which case
`installed` and `local_source` are both null rather than one of them being invented.

| Parameter | Description |
|---|---|
| `target` | `auto` \| `tor` \| `firefox` |
| `install` | Tor Browser install root, or a Firefox program directory; auto-discovered when omitted |
| `online` | Opt in to a single request that asks a public endpoint for the current version. **Default `false`**, so the default posture is offline; the installed version is always read locally |
| `proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` or `socks5://127.0.0.1:1080` |

**It routes through the local proxy automatically**: first the `HTTPS_PROXY` / `ALL_PROXY` environment variables, then the Windows system proxy (WinINET `ProxyServer`). Override with `proxy`, or pass `"none"` to force a direct connection.

> Why this is needed: Node's built-in `fetch` **does not read the system proxy**, so on a network that requires one it goes straight to `UND_ERR_CONNECT_TIMEOUT`. This implements HTTP CONNECT and SOCKS5 tunnelling from the stdlib.

### `aikawamei_layer_assess`
Layer arbitration. Takes scenario characteristics, returns a recommended channel + steps + warnings + a **non-coverage list**.

| Parameter | Description |
|---|---|
| `content_sensitive` | Does the content itself need protection (what happens if it is read) |
| `metadata_sensitive` | Does the fact of communicating need protection (what happens if who-talks-to-whom is known) |
| `realtime` | Is a realtime / near-realtime round trip required |
| `counterpart_capability` | `email-only` \| `can-install-tools` \| `signal-capable` \| `tor-capable`. The upper bound of the counterpart's tooling -- this usually caps the whole design |
| `must_leave_no_third_party_copy` | Must no third party retain a copy |
| `endpoint_shared_or_seizable` | Can the endpoint be accessed by others or seized |

Key behaviors:
- `metadata_sensitive + realtime` -> reports a **hard conflict** (real time couples the two ends' clocks tightly, which is perfect material for timing correlation)
- `content_sensitive` and not metadata-sensitive -> **discourages** over-tradecraft (high-risk tradecraft is itself the most conspicuous signature)
- `counterpart_capability: email-only` -> points out that the ceiling on the approach is pressed very low
- every assessment carries `does_not_cover`

### `aikawamei_checks`
Query the check surface as data. Lists every check this build performs, what each one reads,
and -- per check -- **what that check does not cover**. It reads nothing and audits nothing.

| Parameter | Description |
|---|---|
| `target` | `tor` \| `firefox` -- restrict to the checks one target produces |
| `layer` | `all` \| `build` \| `transport` \| `crypto` \| `metadata` \| `endpoint` |
| `id` | Look up a single check instead of listing |

Key behaviors:
- The surface is a declared catalog rather than something you can only learn by reading control flow, and each entry carries its own boundary text -- the shared `boundary_notice` deliberately does not enumerate per-check limits
- An audit response reports the catalog version, a structural digest, and whether the run **conformed** to it (`unknown` ids, severities outside a check's declared set). A mismatch is a defect in this repository, never a statement about your machine
- Also reports which checks did not fire. That is not an error: a check whose subject is absent does not fire

### `aikawamei_baseline`
Posture **drift**. A single audit answers "what does the configuration look like now"; it
cannot answer "did anything move since last week". `mode=capture` records the current audit;
`mode=diff` compares a stored record against a fresh audit.

| Parameter | Description |
|---|---|
| `mode` | `capture` (default) \| `diff` |
| `baseline` | A previously captured baseline; a capture *response* is accepted as well as a bare record |
| `baseline_path` | Path to a baseline JSON file to read instead |
| `target`, `install`, `profile` | Which target to audit, as in `aikawamei_audit` |

Key behaviors:
- **A baseline stores fingerprints, never evidence.** This is load-bearing: the audit's own argument is that state files, guard sets, key filenames and paths are the sensitive residue, so a baseline that recorded them would be a tidy copy of exactly what the tool tells you not to keep. Each entry keeps a digest of the evidence -- enough to detect a change, useless to anyone who obtains the file
- The diff **refuses rather than guesses**: two records from different installs or profiles differ in almost every line, and their difference is not drift, so that is reported as `subject-mismatch` instead of a number that looks like an answer
- A moved check catalog is **not** drift. When the surface changed, the comparison is restricted to the checks both records carry, and the difference is flagged separately
- Accepts a capture response as well as a bare record, so redirecting a capture straight to a file works
- Stateless: nothing is written anywhere. You keep the baseline and hand it back

### `aikawamei_handoff`

What would travel with a directory you are about to give someone else. Point it at the directory and
it reports what it finds **by name**, and nothing else.

| Parameter | Description |
|---|---|
| `path` | The directory about to be handed over |
| `tor_install` | Optional: a Tor Browser install root to use for the onion-authorization part, instead of the one that would be discovered |
| `layer`, `min_severity` | Filters, as in `aikawamei_audit` |

It looks for five things, all of them catalog data rather than code -- see `aikawamei_checks` for the
per-check limits, which are stated by each check rather than summarized here:

- **Key-shaped names**: `id_rsa`, `*.pem`, `*.kdbx`, `.env`, `credentials.json`, `known_hosts` and similar, anywhere in the tree
- **Editor and OS residue**: `Thumbs.db`, `.DS_Store`, `desktop.ini`, swap and backup files
- **Version-control entry**: `.git`, `.hg`, `.svn` -- a repository carries every revision, including the ones deleted from the working tree
- **Build and dependency artefacts**: `node_modules`, `__pycache__`, `target`, `dist`
- **OnionShare presence**: whether a share can be started from this machine at all

When a Tor Browser install is present, its **onion client authorization state** is included, because
that is the other half of preparing a delivery: it answers who can reach the service the package is
being sent over. Those checks are declared for this target as well and are gated on the bases a Tor
install supplies, so with none present they stay silent rather than reporting an absence they cannot
establish -- and the response names whichever install was used.

**The limit that matters most here**: it reads names and sizes, **never file contents**. A key
pasted into `notes.txt`, or a password inside a spreadsheet, is invisible to it. So a scan that
finds nothing is **not** a clean bill of health; it means nothing matched a name. The CLI says so at
the point where a reader would otherwise take silence for approval.

### `aikawamei_content`

The one tool here that reads file **contents**, because a key pasted into `notes.txt` has a perfectly
ordinary name and no amount of looking at names will find it. It reads the paths you name and reports
what is in them: key material stored as text, credential-shaped strings, and patterns taken from
rules-as-data -- including a local ClamAV signature database, if you point it at one.

| Parameter | Description |
|---|---|
| `paths` | Files or directories to scan, named explicitly. **Required**: there is no default root, and omitting it is an error rather than a whole-machine scan |
| `max_bytes` | Bytes read per file. Default 1 MiB, ceiling 8 MiB, and the ceiling cannot be raised by argument |
| `max_files` | Entry ceiling for the call. Default 2000. What it left out is reported, not dropped |
| `clamav_dir` | Optional directory of local ClamAV signature files (`.hdb`, `.ndb`), read as text and used as extra rules |
| `layer`, `min_severity` | Filters, as in `aikawamei_audit` |

Four limits make reading contents defensible, and each one is checkable rather than promised:

- **No derived roots.** The caller names the paths. Nothing walks the profile, the temp directory or a
  drive letter, and there is no argument whose absence means "the whole machine".
- **A bounded prefix.** At most `max_bytes` per file. A file larger than that is reported as **not
  evaluated** wherever a whole-file signature would have been needed, because "we did not look" and
  "we looked and found nothing" are different answers and only one of them is evidence.
- **A closed rule vocabulary.** A literal string or a byte sequence in hex. No regular expressions, no
  nesting, no composition, no `eval`. A pattern language is a programming language with worse error
  messages, and it becomes an injection surface the moment the pattern comes from a file someone else
  can write. Each rule declares what it does **and does not** cover, and the report carries that
  boundary next to the hit rather than summarizing it away.
- **No write path at all.** This is the part to be precise about, because the standing instruction for
  this work item is that judgement must never repair: nothing in this tool deletes, moves, renames,
  quarantines, changes permissions, or "cleans" a hit. That is not a flag defaulting to off -- the
  capability does not exist in the module, and the suite asserts that two ways: the source contains no
  mutation API, and the scanned tree is hashed before and after a full scan.

**On ClamAV, and on YARA, without claiming compatibility.** The idea borrowed from YARA is that rules
should be a reviewable artifact rather than control flow; YARA's syntax is not implemented and
compatibility is not claimed. ClamAV's `.hdb` and `.ndb` files are plain text with a published format,
so a local copy is read as text and its patterns used as data -- but `clamscan` is never run, nothing is
downloaded, and only the two simplest line forms are parsed. Every line outside them is counted and
reported as skipped, because a parser that silently ignores what it does not understand turns a partial
database into a confident scan.

**One property worth knowing before you point it at a directory:** the rule table is itself a text file
that contains the patterns it looks for, so a scan that includes `lib/content.mjs` will report that file.
That is not an exception to be special-cased; it is what a rules-as-data table is. The same is true of
this README, and of any log or transcript that quotes a rule.

### `aikawamei_sessions`

What the browser-automation toolchains left on this machine. Playwright, Selenium, Puppeteer,
DrissionPage and Appium all persist the thing that makes an automated session work -- cookies,
localStorage, bearer tokens -- and none of them reports where it went.

| Parameter | Description |
|---|---|
| `roots` | Directories to scan, given as a repeated flag on the command line (`--roots A --roots B`). Omit to use the roots derived from the environment: the user profile, the application-data directories, the temporary directory, and the working directory |
| `vault` | Optional: append one record of this run to a tamper-evident chain at this path. **Nothing is written unless this is given** -- every other tool here is read-only, and one that wrote on every call would break the notice it carries. The record always holds counts; it holds the paths only inside a sealed payload, and only when `AIKAWAMEI_VAULT_PASSPHRASE` is set (an environment variable rather than an argument, because arguments are visible in the process list and in shell history) |
| `scope` | Optional: the roots you claim as your own, as a repeated flag. Given one it becomes an allowlist and every root outside it is refused rather than scanned. Omit it and the default rules apply: a network path, or a profile directory belonging to a different user, is refused |
| `layer`, `min_severity` | Filters, as in `aikawamei_audit` |

**The scope guard, and exactly how much it claims.** A path says nothing about who owns it, and no
amount of reading establishes it. So the guard does the two things that are possible rather than the
one that is not:

- **By default it refuses two shapes** -- a UNC or network path, and a profile directory belonging to
  a user other than the current one. Those are the shapes that most often mean someone else's data.
- **A declaration is an allowlist.** Name the roots you own and everything outside them is refused.
  A declaration of nothing refuses everything, visibly: the response reports an empty root list and
  names what it declined, rather than quietly widening back to a default the caller did not ask for.
- **A link cannot walk out of scope.** Where the path exists its real path is resolved as well, and
  **both** forms must be inside.

What it is **not**: a boundary. A borrowed laptop, a colleague's directory mounted at an unusual
path, or a share mapped to a drive letter are all outside what these rules recognise. The response
carries that in its own words and reports `verified: false`, because a declaration is a claim by the
operator and this tool cannot check it.

Five classes, all of them catalog data rather than code:

- **Plaintext session exports** -- Playwright's `storage_state.json` and `storageState.json`, a `cookies.txt` jar, `*.cookies.json`. These are plaintext by design, so a copy of the file is a live account
- **HTTP archives** -- `*.har`, which records full request and response headers -- `Authorization`, `Cookie`, `Set-Cookie` -- for every exchange it captured
- **Profile stores** -- `Cookies`, `cookies.sqlite`, `Login Data`, `Local State`, `key4.db`. A profile directory is a credential store, not a cache: the key that opens it sits in the same directory, so anything running as that user can read it
- **Profile directories** -- `user-data`, `.auth` and similar, which is what a persistent-context launch is handed
- **Report and trace artefacts** -- `playwright-report`, `test-results`, `*trace*.zip`

Every hit names the path, the size, the age, and whether it sits inside a **git working tree**.
The roots that were actually scanned are listed in the response, including the ones that turned
out not to exist, and a root nested inside one already scanned is reported as skipped rather than
counted twice.

**Two limits, both reported rather than left to be found.** The walk is bounded by depth and by
entry count; when either bound stops it, the root is flagged `truncated`, with `depth_limited`
naming which bound was responsible -- a partial scan presented as a complete one would be the
worst possible answer from a tool whose whole output is an assurance about a tree. And the
questions it cannot answer travel in the response as `not_determined`, each with the command that
answers it: **which paths git ignores, and which were ever committed** (`git check-ignore -v`,
`git log --all --`), whether a session export is still valid, and what any of the files contain.
The last two are refused for the same reason nothing here is ever opened: establishing whether a
session works means presenting the cookies to the site, and reading a credential store in order to
describe it makes a copy of the credential.

### `aikawamei_triage`

Answer a narrow question about this machine: **is there a foothold, and where.**

| Parameter | Description |
|---|---|
| `windows_root`, `user_root`, `app_data`, `local_app_data`, `program_data` | Where the surfaces are read from. Each defaults to the environment variable Windows sets (`%SystemRoot%`, `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%ProgramData%`); with none of them the surfaces below that root are reported as **not looked at** rather than guessed at |
| `writable_roots` | Where to look for executables; defaults to the two application-data directories |
| `window_minutes`, `min_cluster` | The correlation window (60) and how many entries a window needs (3). A window is only reported when it spans **more than one source** |
| `timeline_limit` | How many timeline entries come back, most recent first (60). `timeline_total` is reported beside it, so a bounded answer never reads as a complete one |
| `scope`, `vault` | As in `aikawamei_sessions` |

Five surfaces, all of them **files**. Nothing is executed, and no file is opened beyond reading its
bytes:

- **WER crash reports** -- `Report.wer` under the user's reporting queues. A process that ran and crashed leaves its path here. This is the surface that caught the miner on this machine: the executable sat in a made-up folder under `%APPDATA%\Microsoft\Windows\Themes`, and a crashing run left a report naming it
- **Prefetch** -- the filename names the executable and the mtime is its last run. The body is XPRESS-compressed and is deliberately not decoded: the name and the time are what a timeline needs
- **Startup folders** -- both of them
- **Scheduled tasks** -- XML, **UTF-16LE**, with no file extension. Fields are read by name with a pattern rather than with a parser, so an unusual task can come back with fields missing
- **Executables under the locations anything can write to** -- because "an executable in `%APPDATA%` that something autostarts" is the shape being looked for

**The correlation is the point.** One artefact is a fact about one thing; several kinds of artefact
inside one window is a foothold being established. A cluster therefore has to span more than one
source -- five Prefetch entries in an hour are five programs that ran, which is what an ordinary hour
looks like.

**What it declines to guess about.** The registry surfaces are listed with the command that answers
each, rather than attempted: Run and RunOnce, the service table, Amcache and ShimCache, and
Defender's detection history. Reaching any of them means running a program, and this tool runs
nothing -- `reg query`, `Get-Service`, `AmcacheParser`, `Get-MpThreatDetection`. **A negative answer
here does not mean the machine is clean**, and the response says so.

### `aikawamei_collect`

Copy what a triage run found -- or any paths you name -- to a destination you name.

| Parameter | Description |
|---|---|
| `paths` | The files to copy. Feed it what `aikawamei_triage` reported, or name your own |
| `destination` | Where the copies go. **Required**: this tool writes, and it will not choose where. Refused if it sits inside anything named in `sources` |
| `sources` | Optional: the trees being collected from, for the out-of-band check. Defaults to `paths` |
| `max_bytes` | Per-file ceiling, 64 MiB by default. A file above it is refused and recorded **with its size** |
| `scope`, `vault` | As in `aikawamei_sessions` |

**This is the one tool here that writes**, and its boundary notice says so. It says both things it
does -- that it writes files at paths you name, and that it never touches the network -- because a
notice chosen from a ranking could only ever have said one of them. What it writes is a copy: **the
original is never modified, moved or re-timestamped**, and the copy carries the original's mtime so it
lines up with everything else in the case.

Collection runs **most perishable first**, because the things about to be pruned are the things nobody
can collect later. The parts of that order a tool that runs nothing cannot reach -- memory, live
network state, the process table, open handles -- are listed with the instrument that answers each
(`winpmem`, `Get-NetTCPConnection`, `Get-Process`, `handle.exe`).

Every copy is hashed as it is written, and the **manifest is a hash chain**: each entry carries the
hash of the line before it, so an edit or a deletion in the manifest is caught by
`aikawamei_vault --path <destination>/manifest.jsonl`, which needs no passphrase.

### `aikawamei_vault`

Verify the tamper-evident record another run left behind.

| Parameter | Description |
|---|---|
| `path` | The record file to verify |
| `expect_length`, `expect_head` | Optional: the length and head a previous verification reported |

The record is a JSONL chain in which **each line carries the hash of the line before it**, so an edit,
a deletion, an insertion, a reorder or a blank line breaks the link at the first affected record --
and the tool reports **which index** to look at. Two properties are deliberately separate:

- **Integrity needs no key.** The hash is taken over the *sealed* line, so someone who cannot read a
  single entry can still prove the sequence was not altered. Integrity does not depend on
  confidentiality, and confidentiality does not depend on integrity.
- **Confidentiality is per record.** A payload is sealed with AES-256-GCM under a key derived from the
  passphrase with scrypt, with the cost parameters recorded in the envelope so an opener uses what the
  sealer actually used rather than a guess.

**What it cannot see is stated rather than implied: a chain cannot see its own tail being cut.** The
remaining records are still perfectly linked, so that is why a verification returns a **receipt** --
length and head -- and why `expect_length` / `expect_head` exist: only a caller who kept the receipt
can detect a truncation. Nothing here signs, so the record shows that a sequence was not altered after
the fact; it does not establish who wrote it.

### `aikawamei_self`

Compare this installation against a manifest you kept, and name every file added, removed or altered.

| Parameter | Description |
|---|---|
| `root` | The installation root. Defaults to the directory this tool is installed in |
| `baseline` | Optional: a manifest written by an earlier run, to compare against |
| `out` | Optional: write the manifest of the present state here, to keep for the next run |
| `chain`, `expect_length`, `expect_head` | Optional: verify a record chain, against the receipt a previous verification reported |
| `sign_key` | Optional: an ed25519 private key (PEM). The manifest is signed with it, so someone else can verify what you recorded **without trusting the file** |
| `verify_key`, `signature` | Optional: check a signature against a public key |
| `vault` | Optional: append a record of this run to a chain, as elsewhere |

The manifest covers the files that decide what the tool does -- `lib/`, `cli/`, `mcp/`,
`package.json`, `.gitattributes` -- and not the prose, because a README does not change what the tool
does. The comparison reports four outcomes **separately**: added, removed, changed, and untouched,
with the untouched list as the control that gives the other three their meaning.

**It detects a change; it prevents nothing, and that is deliberate.** On a machine whose owner can
become root, an agent that survives its owner is one the owner can no longer account for -- which is
the definition of the software this project is written to find. So the honest form of "protect
yourself" is smaller and real: make the change visible. A holdout on your own land is worth something
not because it cannot be moved, but because moving it is **seen**.

**A manifest can be signed, and its signature is portable.** `--sign-key` signs the manifest with an
ed25519 key and `--verify-key` checks it, so a manifest kept off this machine can be shown to be the
one you recorded without anyone having to trust the file it arrived in. Ed25519 because it has no
parameters to get wrong: no curve to pick, no digest to choose, no padding mode whose absence is a
vulnerability. What signing proves is narrow on purpose -- that the manifest was signed by the holder
of the key and has not changed since. It does not prove the machine was clean when it was taken. The
bytes signed are built from a fixed field list in a fixed order (`canonicalManifest`), because signing
is worthless if the bytes signed are not the bytes verified.

**And it can refuse to start.** Set `AIKAWAMEI_VERIFY_SELF` to a manifest you kept, and the executable
compares the installation against it **before any tool runs**: on a mismatch it prints what changed on
stderr, puts nothing on stdout, and exits 3. It is opt-in, it is loud, and it **repairs nothing** --
because a gate that quietly fixed a modified installation would be a program that changes itself on a
machine whose owner did not ask, which is the shape of software this project is written to find.
Failing loudly and stopping is what a tool can do honestly; surviving its owner is what a rootkit does.

The limit is in the response rather than only here: **an installation that has been removed cannot
run, and so cannot report that it is gone.** The only thing that answers that question is a copy of
the manifest kept somewhere this machine cannot write to. Attribution is refused for the same reason
-- a digest says what changed, never who did it.

### `aikawamei_attribution`

The three questions a takedown report can answer honestly, for a domain, an address, an ASN or an
email: **who is responsible for it**, **who can act on it**, and **how the report gets written without
overclaiming**. It answers them from tables in the tool, and it reaches the network only when you say
so, once per call.

| Parameter | Description |
|---|---|
| `targets` | Domains, IP addresses, ASNs (`AS15169`) or email addresses. **Required**: the tool reports on what you name and has nothing to say about an unnamed adversary |
| `allow_lookup` | Whether to perform **RDAP over HTTPS**. Off by default; the response records the lookup rather than implying it |
| `tlp` | Which sharing level the report outline is written for. The outline carries what that level permits |

**The question it does not answer is "who did it".** That is the question an audit is least able to
answer honestly, and this project has a case of getting it wrong: a lost account was read as "there is
an infostealer on this machine" when the evidence supported two independent events. So every evidence
grade names the **source** of a record, never how much it suggests:

- `registry-record` -- returned by the registry's own RDAP service
- `self-declared` -- something the operator states on a page it controls
- `dns-answer` -- a record served for the name, which shows control of the name at that moment and nothing else
- `third-party-report` -- a claim in someone else's report, which is evidence that a claim exists
- `unattributable` -- a first-class answer and the default whenever nothing holds

There is no grade for "likely" and none for "probable"; the suite asserts that closed set, because a
vocabulary that drifts toward probability is an attribution that has not been made. A lookup that
fails -- a 404, a rate limit, an unreachable service -- comes back as unattributable rather than as a
record with no abuse contacts, since the record was not read.

**The channels are candidates and say so.** `abuse@<domain>` is a convention, the registrar is who can
actually suspend a domain, and for an address the RIR's published contact is usually the only route
that ends in action. Each is labelled unconfirmed, with what confirming it would require.

**It sends nothing, and it does not speak whois.** No mail, no form, no filed report: it produces a
local document and a list of channels, and a person decides what leaves the machine. A whois server is
named as a **reference for a person**, not as a capability, because plain-text whois is a different
protocol on a different port than this project has a path to. Naming an operator publicly is out of
scope by instruction rather than by omission -- a tool that could publish an address would be the
exposure route this work item rules out.

**The report outline carries the two sections most reports omit**: what the report does **not** claim
(no actor, no motive, no correlation from timing, no claim that a host is the actor's own), and what
its **sharing scope** is, in the document rather than in the message that carries it. The bootstrap
table for RDAP is written down with the date it was taken and the URL of the authoritative file, so a
snapshot is never presented as current.

---

## 5. The four-layer model

```
Content layer   Can anyone else read the content itself?
                -> End-to-end encryption. The best-solved layer; not the bottleneck.

Metadata layer  Can anyone else learn who talks to whom, when, and how often?
                -> mixnet / metadata-hiding messenger / asynchronous mailbox / onion service.
                -> [Content encryption helps this layer by roughly zero] -- where the vast majority of approaches go wrong.

Endpoint layer  What did this machine in your hands leave behind? What if it is taken?
                -> Environment isolation / full-disk encryption. Cryptography cannot reach it.

Social layer    What will people say, keep, or be asked?
                -> No technical solution.
```

What `aikawamei_audit` examines is the **static residue of the metadata layer and the endpoint layer** (the remaining layers get posture-compliance checks only).

---

## 6. Measured baseline

Results from a run on this machine (Windows, Tor Browser installed on a non-system drive,
network requiring a proxy). A snapshot rather than a specification: the version numbers and the
guard count are what this install had, and the cache sizes in particular grow every time the
browser is used, so they will not match a later run. The point of the section is the shape of
the output and which layers speak up, not the arithmetic.

```
Build layer          Tor Browser 15.0.21 / Firefox 140.15.0 / Tor 0.4.9.11
                     version check -> outdated: 15.0.21 -> 15.0.22
Transport layer      Snowflake bridges x2 (built-in type), uTLS mimicry hellorandomizedalpn,
                     domain fronting fronts=, lyrebird ships 8 PTs, Conjure
Authorization layer  ClientOnionAuthDir configured (empty directory = feature ready, not enabled)
Metadata layer       state 11.9 KB: 22 guards (sets default + bridges), 266 circuit build timings,
                     descriptor cache 35.5 MB + 8.4 MB, profile first use 2025-11-21,
                     places.sqlite 5.0 MB (browsing history present -- worth a manual check)
Endpoint layer       Drive E, no residue in user or temp directories, persistent install
```

---

## 7. Verification

```bash
npm test              # all traversers, exit code 0
npm run test:cov      # coverage report (--gap prints the uncovered lines in detail)
npm run test:net      # network-layer protocol behavior only
npm run test:matrix   # contract traversal only
npm run test:emblem   # the seal only; needs no source work
```

| Traverser | What it asserts | Scale |
|---|---|---|
| `test/selftest.mjs` | **Semantic correctness** (Tor target): should this branch report at all, and at what severity. Also owns the serializer: sharing is not circularity, `toJSON` is honoured, `undefined` behaves as it does natively, and runs `aikawamei_handoff` against a real directory rather than a fake one | **261 items** |
| `test/matrix.mjs` | **Contract invariance + robustness**: however it is called, the output contract does not break | **277 calls / 557 contract checks / 0 violations** |
| `test/net.mjs` | **Protocol behavior**: local mock proxy / SOCKS5 / a real TLS handshake over the tunnel / echo / HTTP servers | **54 items** |
| `test/firefox.mjs` | **Semantic correctness** (Firefox target): profile discovery, retention findings, and the credential-exposure line | **151 items** |
| `test/emblem.mjs` | **The seal**: opening with the source work, and refusing a wrong source, an altered payload, tag or nonce, or a swapped container. Built on a synthetic stream, because the claim under test is that a machine *without* the work cannot open it | **94 items** |
| `test/checks.mjs` | **The catalog against the code, in both directions**: every id the code emits is catalogued, every catalogued check has a producer, no two checks own the same fact slot, every entry states a boundary, no template leaves a placeholder unresolved. Plus every branch of every probe, driven through an injected filesystem so a branch reachable only on another platform still runs, every value predicate asserted directly, and the literal rendering of migrated checks checked character for character | **953 items** |
| `test/sessions.mjs` | **The sessions target**: the five classes it finds, the repository answer asserted in both directions (inside a tree, and outside every tree), and the two bounds as PAIRS -- a file at the depth limit and the same file one hop past it, an entry count that fits and one that does not. The roots are asserted against a synthetic environment, because a hardcoded path would pass every functional test on the machine it was written on | **113 items** |
| `test/vault.mjs` | **The record**: sealing (round trip, and a refusal for an altered payload, tag, nonce or salt, each violating exactly one field), the chain (an edited, deleted, inserted, swapped, blanked or forged record, each caught and each naming its own index), and integrity **without the passphrase** -- which is the whole point of hashing the sealed line. The limit is asserted too: the same truncated chain is refused against a kept receipt and passes without one | **64 items** |
| `test/scope.mjs` | **What may be read**: containment on a path boundary (`/a/b` does not contain `/a/bc`, the defect a prefix comparison hides), both comparison modes driven from one machine, the two shapes refused by default, a declaration as an allowlist, an empty declaration refusing everything, and a directory link that resolves out of scope. The claim is asserted as small as it is: nothing here establishes ownership | **62 items** |
| `test/triage.mjs` | **Intrusion triage**: the two artefact surfaces that are NOT UTF-8 (a reader that decodes them as UTF-8 reports every task as having no command, so the fixture is written as real UTF-16 bytes and the assertion is that no NUL survives), the five readers, the time alignment, and the correlation rule with its control -- five entries from ONE source must produce no cluster while a mixed window must. Also the judgement boundaries: a warning that is not a verdict, and the control that the same shapes in their proper places produce nothing | **91 items** |
| `test/collect.mjs` | **The one part that writes**: that the ORIGINAL is untouched (digest, mtime and size recorded before and asserted unchanged after -- a collector that normalised what it collected would have destroyed it), that a copy carries the original's mtime so it lines up with everything else in the case, that the destination is refused when it sits inside what is being collected and allowed when it is a sibling, that the manifest is a chain the vault's own verifier can check, and that the order of volatility is stable WITHIN a class so the manifest is reproducible | **70 items** |
| `test/selfcheck.mjs` | **Watching the installation itself**: that the diff reports all four outcomes separately (added, removed, changed, untouched -- with the untouched list as the control that gives the others meaning), that each side of the comparison sums to its own count rather than to one shared total, and that the limits are asserted rather than described: an installation that has been removed cannot report that it is gone, and nothing here prevents anything | **71 items** |
| `test/baseline.mjs` | **Drift, and the privacy claim**: key-order-independent fingerprints, every refusal branch, and the assertion that a captured baseline contains **no** evidence -- built with a marked value that must not appear in the output. Tested over parsed values, not raw JSON, because `JSON.stringify` escapes backslashes and a substring test would pass for the wrong reason | **113 items** |
| `test/mcp-smoke.mjs` | **The portable half**: a real MCP client sees exactly the core's tools, and every response names a versioned schema. Its calls are aimed at a synthetic install, so it does not depend on what the runner has | **78 items** |
| `test/coverage.mjs` | **Evidence of the traversal**: which lines were never executed | **4585/4635 = 98.9%** on Windows, **4533/4626 = 98.0%** on Linux; the Linux figure is the lower one and is what the gate is set against |

Coverage is a property of the environment as much as of the code, and both numbers are given
because quoting only the higher one would be misleading -- but the two environments differ by
platform *and* by proxy, which is why each row says which. The tunnel's success path, writing a
request after the TLS handshake and reading the response back, used to be entered only where a
proxy was reachable, so the runner never ran it and the gate had to be set to that floor rather
than to the code. `test/certs/` now lets the suite drive a real handshake over the tunnel, so
that path is covered wherever the suite runs and the gate is back to 97.

What remains uncovered is `detectProxy` and only `detectProxy`. With a proxy variable set it
returns inside the loop, so line 92's platform test needs a machine with no proxy variable at
all, and line 93, `readWininetProxy`, needs Windows. Windows therefore reports 190/190 -- its
proxy arrives through WinINET, not the environment -- while Linux reports 189/190 with no proxy
variable and 188/190 with one. None of that is a behavioural difference between platforms: the
same code runs, and only the fixture that reaches it differs.

`selftest`, `matrix`, `firefox` and `emblem` use **synthetic fixtures** (`test/fixtures.mjs`: good / degraded / minimal / self-inconsistent / boundary, for both targets; the emblem suite assembles its own FLAC stream from known field values), so they **do not depend on whether Tor Browser or Firefox is actually installed on this machine** and reproduce on any machine. `net` uses local mock servers and depends on neither the public internet nor a real proxy. The emblem suite additionally depends on no source work being present, which is the condition it is testing.

The `matrix` contract includes: serializable, `boundary_notice` permanent, **no safety assertions may appear**, finding fields complete, ordered by descending severity, `tally` consistent with reality, layer and severity filtering exact, `does_not_cover` non-empty, and 16 sets of malformed input must not throw.

**Coverage is measured on Windows and Linux, because one platform is not enough.** Windows alone reports 11 uncovered lines and Linux alone reports 40, but the two sets barely overlap: each platform covers the branches the other cannot reach -- the Windows drive-letter scan and WinINET proxy read are unreachable on Linux, and the `/usr/lib/firefox` candidates are unreachable on Windows. Only **5 lines are never executed anywhere**, and they are named in [`PROOFREADING.md`](./PROOFREADING.md) rather than papered over. The first Linux run also failed three suites, all of them test-portability defects that CI would have hit on its first run; those are recorded there too, together with every defect found during traversal and proofreading.

---

## 8. Design discipline (read this before changing anything)

1. **Read-only**. Does not start Tor, does not change configuration, does not write files. The only networking is the version check, and it is off unless it is asked for.
2. **`boundary_notice` is permanent**. Every return of every tool carries it -- **error paths included**. Do not make it optional.
3. **The auditor makes no unfounded assertions**. For example: guard entries in Tor 0.4.x are written `Guard in=default rsa_id=...`, and in the old style `EntryGuard ...`. Recognizing only one format produces a false "no guards" **false positive** -- this trap was hit in practice. When unsure, emit `info` and say plainly "please confirm manually".
4. **Positive findings must be shown**. Default `min_severity: ok`. Hiding `ok` makes the report look one-sided and creates needless alarm.
5. **No second implementation**. The MCP server and the CLI share the same single `TOOLS[].execute`.
6. **`aikawamei_layer_assess` never claims safety**. It must be able to say loudly "I do not solve this".
7. **Line coverage is not branch coverage**. When a ternary branch on a line is never taken, that line still counts as covered -- a tautological ternary (`x ? "a" : "a"`) is **invisible to coverage** and can only be caught by human proofreading. Coverage is necessary evidence, not sufficient evidence.
8. **Tests must not pass for the wrong reason**. During one proofreading round, a blackhole-timeout test "passed" because the port was wrong, so it never actually reached the TLS timeout branch under test -- coverage is what dragged it into the light. Assertions must target the exact behavior, not "if there is an error, count it as a pass".
9. **Fixtures are shared**. `test/fixtures.mjs` is the single source of truth. Inlining a copy means two sources of truth that drift apart on their own.
10. **Filter parameters must be echoed back**. An unknown value falls back to the default, and the filter that actually took effect goes into `applied_filter` -- otherwise a caller who mistypes just gets an empty result and no idea why.
11. **A boundary claim that is false in its first line is worse than no claim at all.** Every check therefore states its own limit in the catalog (`does_not_cover`), and a boundary that cannot be honoured must be removed rather than softened. The `disk-encryption` check exists in this spirit: on Windows a static, unprivileged audit genuinely cannot read a volume's encryption state, so it reports `undetermined` and names the command that answers it, instead of guessing in either direction.
12. **A stored baseline must never contain evidence.** It keeps one fingerprint per check. A baseline that recorded guard names, key filenames or paths would be a tidy copy of exactly the residue this tool tells you not to keep -- and it would diff just as well, so nothing but this rule stops it.
13. **Declared data and code must agree in both directions.** `test/checks.mjs` scans the sources and requires that every id the code emits is in the catalog *and* that every catalogued check has a producer. A table that nothing enforces is decoration.
14. **Serialization must not confuse sharing with circularity.** The same evidence object is reachable from both `findings` and `facts`; a serializer that tracks every object ever visited rather than the ancestors of the current path turns the second view into `"[circular]"` and silently drops the data (see D35 in `PROOFREADING.md`).
15. **The output order is a contract.** Findings sort by descending severity, then by layer in the order `LAYERS` declares them, then by id. Before this, ties kept ASSEMBLY order, so moving a check from one function to another silently changed where a finding appeared while every one of its fields stayed identical -- which is exactly what happened during the catalog migration. An order that can be recomputed from the findings themselves cannot drift.
16. **One evidence shape per probe.** Every `path-residue` finding carries `{path, size, mtime, age_days}`. Three shapes used to exist because three pieces of code had each built its own; they were unified only after the migration had been proven field-for-field, so that the suites could still distinguish a faithful move from a broken one. `stale` was dropped rather than carried: it is derivable from `age_days` and the entry's own threshold, and a recorded fact that can be recomputed is a fact that can disagree with its input.
17. **Accept what the caller actually has.** `aikawamei_baseline` takes a capture *response* as well as a bare record, because redirecting a capture to a file is the obvious workflow and what lands in the file is the response.
18. **Dynamic checks are refused, and the two kinds are refused for different reasons.** Querying Tor's ControlPort is refused for a **structural** reason: an audit whose result depends on whether a service happens to be running is no longer deterministic, and determinism is precisely what the baseline and drift feature rests on -- a capture that cannot be reproduced cannot be diffed. Testing whether a configured bridge is reachable is refused for an **operational** reason that has nothing to do with scope: **dialing a bridge from the auditor manufactures the metadata the audited user is trying to avoid.** Tor's protection against traffic correlation rests on a user's traffic not being distinguishable or linkable; a connection to a bridge, from that user's address, at a moment of that user's choosing, is exactly the observable pattern an adversary needs to find and fingerprint that bridge's use. Such a check would not merely risk harm, it would **be** the harm. Where a dynamic answer is genuinely needed, the tool does what `disk-encryption` already does: report `undetermined` and **name the command that answers it**, leaving the decision to create traffic with whoever owns the consequences.
19. **The boundary notice names every class a tool declares, not the strongest one.** It was derived by ranking the operation classes and writing one sentence from whichever ranked highest, which is sound while the classes are ordered -- reading, looking up, sending -- and wrong the moment two of them are not. `writes` and `lookup` are not comparable: a tool that copies files **and** asks a public endpoint, described by whichever class ranked higher, is described truthfully and **incompletely**, and a boundary claim that is true by omission is the one shape of false this project treats as worse than saying nothing. So each class contributes a clause, the clauses are joined in a fixed order, and the network sentence is decided separately (`lib/checks.mjs`, `networkClause`). The rank helper and its constant were **deleted** rather than left behind: code that exists only to be tested is decoration.
20. **A tool that writes declares `writes`, and the declaration is checked against the code in both directions.** `test/selftest.mjs` scans each tool's body for the symbols that mean a write and compares that against what the tool declares -- the same enforcement the network already had. It earned its place on the first run by finding two tools that append a record when asked and were still declaring themselves read-only. The clause is shared by all of them and is deliberately general ("writes files at paths you name when you ask it to, and never modifies or moves what it reads") because the three writing tools write different things: a record, a copy, a manifest. With none of those arguments given, nothing is written, and that is part of what the notice says.
21. **A scope is a claim the caller makes, not a check the tool performs.** The guard cannot know who owns a directory, so it does the only honest thing available: it requires the roots to be declared as yours, and then it **enforces the declaration**, refusing anything outside it and reporting the refusal rather than hiding it. Two consequences are deliberate. An **empty or blank declaration refuses everything** -- fail-closed, because a guard that falls back to permissive when given nothing is a guard that is off whenever it is misconfigured. And containment is compared on a **path boundary**, so `/a/b` is not the parent of `/a/bc`; when the target is a link that resolves, **both** the link and what it points at must be inside, or the link is how the guard is walked around.
22. **Collection runs most perishable first, and the copy lands out of band.** The order is RFC 3227's, restricted to what a tool that runs nothing can reach -- and the parts it cannot reach (memory, live network state, the process table, open handles) are **listed with the instrument that answers each**, because an operator who did not know that would take a complete run for a complete collection. The destination is refused when it sits inside what is being collected: a copy kept inside the evidence is not a copy. The original is never modified, moved or re-timestamped, and a copy carries the original's mtime so it lines up with everything else in the case. Every copy is hashed as it is written and the manifest is a **chain**, so an edit or a deletion in it is caught by `aikawamei_vault` with no passphrase.
23. **Detecting is not preventing, and the difference is stated on the response rather than only in the docs.** `aikawamei_self` compares the installation against a manifest you kept and names what changed; it resists nothing, and that is not a limitation to be apologised for. On a machine whose owner can become root, an agent that survives its owner is one the owner can no longer account for -- which is the definition of the software this project is written to find, and the shape of the incident that started it. The honest form of "protect yourself" is smaller and real: **make the change visible.** The limit travels with the answer: *an installation that has been removed cannot run, and so cannot report that it is gone*, and the only thing that answers that question is a copy of the manifest kept somewhere this machine cannot write to.
24. **An integrity gate fails loudly and repairs nothing.** Set `AIKAWAMEI_VERIFY_SELF` and the executable compares itself against the manifest you kept before any tool runs: on a mismatch it names what changed, writes nothing to stdout, and exits 3. The temptation to add "and then restore the file" is the whole danger -- a program that repairs itself on a machine whose owner did not ask is the shape of software this project exists to find, and the line between a gate and a rootkit is drawn exactly there. A gate is also only worth what its baseline is: a baseline it cannot read is refused rather than ignored, because a gate that opens when its own check is missing is not a gate. What it cannot do is stated with it -- **an installation that has been removed cannot run, and so cannot report that it is gone**, and the only thing that answers that is a manifest kept somewhere this machine cannot write to.

25. **A guard protects only the documents it reads.** The check that compares this README's verification table against what the suites actually passed did its job for two rounds -- and `PROOFREADING.md` drifted the whole time, because it was not one of the files the guard opened. Its traverser table said six suites when there were fourteen. A guard is not a property of the repository; it is a property of the files it is pointed at, so it must be pointed at every document that states a number. The same reasoning produced the assertion that every tool has a section in this reference, checked **from the tool list** rather than by eye -- which is how a scripted edit that silently ate one heading was caught.

26. **What a human signed is not something the pipeline may replace.** The Windows artifacts are signed by hand after the build, with a key that lives on one machine and in no repository secret. That makes a re-run of a release tag dangerous in a way a failure is not: `gh release create` refuses a release that already exists, and the tempting fix -- make the step idempotent and upload over it -- would put freshly built, **unsigned** installers in place of signed ones, silently, because replacing an asset and publishing one look identical from outside. The step therefore refuses with the reason, in the log and in the commit status. A failure that states the cost beats a success that removes a signature.

27. **An empty result must be proved to be a result.** A query that failed outright and a store that is genuinely empty return the same thing, and the mistake is believing the second without ruling out the first. Measured here: with a PowerShell 7 `PSModulePath` inherited into a 5.1 session, `Get-ChildItem Cert:\LocalMachine\Root` answered `total=0` for a store holding 73 entries, and `Cert:\CurrentUser\My` answered `total=0` for one holding 5 -- which read as "the trust store is empty" and put a wrong conclusion in a report, twice. The test is to count something that must be there. `total=0` for a machine's root store is not a finding, it is a malfunction.

---

## 9. Next steps

- **The declarative boundary, and where it sits.** Forty-seven of the seventy-one checks are built from catalog data by nine probes (`volume-encryption`, `path-residue`, `path-list`, `dir-entries`, `dir-size`, `json-field`, `config-value`, `static`, `tree-match`). Adding another check of an existing shape is a data change and nothing else. The remaining twenty-one stay `bespoke` because their judgement is compositional -- an aggregate over Bridge lines, a derived category, a merge of three sources, or an evidence field computed from two others. Expressing that as data would need a way to combine predicates, and a data file that can combine predicates is a programming language with worse error messages and worse tooling than the JavaScript it replaced. `config-value` is deliberately the edge of what is allowed: nine fixed predicates, one per variant, first match wins, no nesting.

- **Adding a probe is a design decision; adding a check is not.** The probe vocabulary is the part that needs an argument. A new probe should be added when a *shape* recurs -- a path, a directory, a field, a size, a value comparison -- and not to avoid writing ten lines of logic once.

- Release pipeline (GitHub Release / npm) -- note that `npmjs.com` is hard to reach from mainland China, so **the Git channel is the primary channel**

## License

MIT
