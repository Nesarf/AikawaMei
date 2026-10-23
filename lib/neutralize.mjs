/**
 * AikawaMei - neutralisation list
 *
 * THE FOUR MOVES, AND WHY THE ORDER IS NOT A STYLE CHOICE.
 *
 * A file deleted from disk is a file the next boot can recreate. That is the whole problem with the
 * obvious response to an unwanted program, and it is measured rather than theoretical: a miner
 * re-launched by a Run key comes back the moment the key is left alone, and a key restored from a
 * scheduled task comes back the moment the task runs. So an item that can restore itself has to be
 * starved before it is struck:
 *
 *   sever    cut its way out  -- an outbound block on the program itself, which needs no knowledge
 *                                of the pool or controller it talks to
 *   disable  make it unable to start -- rename, deny execute, or move it out
 *   purge    remove the mechanisms that would bring it back -- the Run key, the service, the task,
 *            the startup shortcut
 *   revoke   end what it stole -- the sessions and tokens it may have carried away
 *
 * For a theft that does not restore itself -- a plaintext session export left in a folder -- the last
 * two swap: revoke first, because once the file is deleted the list of sites it unlocked is gone and
 * cannot be recomputed. So the order this module emits is derived from what was found, not fixed.
 *
 * WHAT THIS MODULE DOES NOT DO: none of it. There is no exec, no spawn, no registry write, no rule
 * creation. Every step is a sentence, a command for a person, its cost, and whether undoing it is
 * possible. A tool that quietly disabled a service could take a machine down with a correct-looking
 * report, and the difference between "here is the move" and "I made the move" is the difference
 * between advice and authority.
 */
import { revokePlan } from "./revoke.mjs";

export const NEUTRALIZE_SCHEMA = "aikawamei-neutralize/1";

/** The four moves, in the order they apply to something that can restore itself. */
export const NEUTRALIZE_LAYERS = ["sever", "disable", "purge", "revoke"];

/**
 * The first path-shaped token in a command line, or null.
 *
 * Autostart records store a command, not a path: `"C:\x\y.exe" --silent`, or a service's
 * `ImagePath`. The exe is what a firewall rule and a rename both need, so it is extracted here
 * rather than passed along as a command line nobody can act on.
 *
 * AN EXECUTABLE EXTENSION IS REQUIRED, and that condition is not fussiness. Measured on this
 * machine: the first run of this module emitted `New-NetFirewallRule -Program
 * "C:\Users\...\AppData\Roaming\Microsoft\Windows\Start"` -- a DIRECTORY, taken from a startup
 * folder entry whose target is the shortcut inside it. Blocking a directory is not a firewall rule,
 * renaming one is not a disable, and both would have read as instructions a person might follow.
 */
export function exeFromCommand(command) {
  const s = String(command ?? "").trim();
  if (!s) return null;
  // Up to and including the FIRST executable extension, quoted or not. Splitting on whitespace was
  // the first version and it broke on `C:\Program Files\x\a.exe`, which is a real ImagePath shape:
  // the split yields `C:\Program`, which looks like nothing and silently produced "cannot name it"
  // for every service installed under Program Files.
  const m = /^"?([^"]*?\.(?:exe|com|scr|bat|cmd|ps1|dll))(?:"|\s|$)/i.exec(s);
  if (!m) return null;
  const candidate = m[1].trim().replace(/,$/, "");
  if (!/[\\/]/.test(candidate)) return null;
  return candidate;
}

/** Whether a path sits somewhere any process can write -- the shape an autostart should not have. */
export function looksUserWritablePath(p) {
  const s = String(p ?? "").toLowerCase();
  return /(\\appdata\\|\\users\\public\\|\\programdata\\|\\temp\\|\\tmp\\|\\downloads\\)/.test(s);
}

/**
 * Components this list will not offer a move for, whatever their location says.
 *
 * MEASURED, and it is the reason this exists: the first run against this machine produced a
 * "block outbound" rule and three disable moves for
 * `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26090.9-0\MpCmdRun.exe`. It sat in
 * ProgramData, which the location rule counts as user-writable, so it passed every test this module
 * had -- and following the advice would have disabled the machine's own anti-malware, which is
 * precisely the outcome an intruder would want from a tool that reports correctly.
 *
 * A location rule cannot tell a security product from an implant that installed itself beside one.
 * So the known ones are named here and reported as "not a move this list makes", which is a
 * different sentence from both "nothing found" and "here is how to disable it".
 */
export const KNOWN_SYSTEM_COMPONENTS = [
  { pattern: /\\windows defender\\/i, name: "Microsoft Defender", why: "blocking or renaming a Defender component removes the machine's own protection, which is the outcome an intruder would want" },
  { pattern: /\\microsoft security client\\/i, name: "Microsoft Security Client", why: "same reason as Defender: it is the anti-malware path, not a payload" },
  { pattern: /\\common files\\microsoft shared\\/i, name: "Microsoft shared runtime", why: "shared components start from here by design; disabling one breaks unrelated software" },
];

/** The four autostart mechanisms, each with the move that removes it and what that costs. */
export const PURGE_BY_SOURCE = {
  "run-key": {
    what: "registry Run key",
    command: (subject) => `reg delete "${String(subject).replace(/^HKLM\\\\?/i, "HKLM\\").trim()}" /f`,
    cost: "the key is gone; the program does not start again from here, and anything else that depended on this entry stops too",
    reversible: false,
  },
  service: {
    what: "automatic service",
    command: (subject) => `sc.exe config "${String(subject).split("\\").pop()}" start= disabled`,
    cost: "the service is set to disabled rather than deleted, so the fact that it existed survives; re-enabling is one command",
    reversible: true,
  },
  task: {
    what: "scheduled task",
    command: (subject) => `schtasks.exe /Change /TN "${subject}" /DISABLE`,
    cost: "the task stops firing but keeps its definition; `/DELETE` removes it instead, and cannot be undone",
    reversible: true,
  },
  startup: {
    what: "startup folder item",
    command: (subject) => `Move-Item -LiteralPath "${subject}" -Destination "$env:USERPROFILE\\Desktop\\quarantine\\"`,
    cost: "moving rather than deleting keeps the file for inspection; it also means the item is one drag away from being live again",
    reversible: true,
  },
};

/**
 * Why a program is on the list at all, repeated on every move that touches it.
 *
 * The list is built from "starts itself from a location anything can write to", which is where
 * unwanted software lives and also where a perfectly ordinary updater lives. A reader who took every
 * entry for a verdict would disable software they meant to keep, so the basis travels with the move
 * rather than sitting in a document nobody opens.
 */
const ON_WHAT_BASIS =
  "This program is listed because it starts itself from a location any process can write to. That is a place to look, " +
  "not a verdict: nothing here judges intent, and the decision that it does not belong on this machine is yours.";

/** How to stop a program from reaching anything, without knowing what it would reach. */
export function severRule(exe) {
  return {
    layer: "sever",
    target: exe,
    action: "Block this program's outbound traffic. A program rule needs no knowledge of the pool, the controller or the resolver it uses, which is why it comes first: the address list is the thing an operator usually does not have.",
    command: `New-NetFirewallRule -DisplayName "aikawamei-block-${String(exe).split(/[\\/]/).pop()}" -Direction Outbound -Program "${exe}" -Action Block`,
    why: "stops the connection while leaving the file in place, so the next steps can be taken without the program re-fetching itself",
    cost: "if this program is a legitimate component, whatever it updates over the network stops working; the rule is named and removable with Remove-NetFirewallRule -DisplayName",
    on_what_basis: ON_WHAT_BASIS,
    reversible: true,
  };
}

/** Three ways to make a program unable to run, in increasing order of permanence. */
export function disableMoves(exe) {
  return [
    {
      layer: "disable", target: exe,
      action: "Deny execute on the file for the current user, leaving the bytes in place for collection.",
      command: `icacls "${exe}" /deny "$($env:USERNAME):(X)"`,
      why: "the file cannot start, and it is still there to hash and copy -- a deletion forecloses both",
      cost: "an ACL is not proof: a process running as SYSTEM or an administrator can restore it, and this does not stop the file being read",
      on_what_basis: ON_WHAT_BASIS,
      reversible: true,
    },
    {
      layer: "disable", target: exe,
      action: "Rename the file so a hard-coded path no longer resolves.",
      command: `Rename-Item -LiteralPath "${exe}" -NewName "$(Split-Path "${exe}" -Leaf).aikawamei-held"`,
      why: "cheap, and it defeats the most common restore mechanism -- a recorded path",
      cost: "a restore routine that scans rather than names will simply find the new name; the extension change also breaks any signature check that ran on the original",
      on_what_basis: ON_WHAT_BASIS,
      reversible: true,
    },
    {
      layer: "disable", target: exe,
      action: "Move the file into a quarantine directory outside every path anything autostarts from.",
      command: `Move-Item -LiteralPath "${exe}" -Destination "$env:USERPROFILE\\Desktop\\quarantine\\"`,
      why: "removes it from the reach of the autostart entries without destroying the evidence",
      cost: "the original path is now empty, which some installers treat as a reason to reinstall",
      on_what_basis: ON_WHAT_BASIS,
      reversible: true,
    },
  ];
}

/**
 * Build the list.
 *
 * `persistence` is what `aikawamei_triage` reported under `triage-autostart-user-writable`:
 * `[{ source, subject, target, at }]`. `sessionHits` is what `aikawamei_sessions` reported:
 * `[{ root, path }]`. Both are optional; the list is built from whatever was given and says which
 * layers it could not fill.
 */
export function neutralizePlan({ persistence = [], sessionHits = [], io = {} } = {}) {
  const steps = { sever: [], disable: [], purge: [], revoke: [] };
  const unresolved = [];

  // --- the persistence points: sever, disable, purge -------------------------
  const seenExe = new Set();
  for (const item of Array.isArray(persistence) ? persistence : []) {
    const source = String(item?.source ?? "");
    const subject = String(item?.subject ?? "");
    const target = String(item?.target ?? "");

    const exe = exeFromCommand(target);
    const systemComponent = exe ? KNOWN_SYSTEM_COMPONENTS.find((c) => c.pattern.test(exe)) : null;
    // A program that lives where only administrators can write is NOT blocked or renamed here. The
    // autostart entry is real, but the file it names is not the shape this pass acts on: the payload
    // may be a temp copy of it, and blocking the program in Program Files would take out something
    // legitimate while leaving the copy alone. Reported instead, with the command that shows it.
    if (exe && systemComponent) {
      unresolved.push({
        layer: "sever", source, subject, target: exe,
        why: `${systemComponent.name}: ${systemComponent.why}. It is on the autostart list because of where it sits, and that is not enough to act on here`,
        how_to_find_out: `confirm the signature before anything else: Get-AuthenticodeSignature "${exe}" | Format-List Status, SignerCertificate`,
      });
    } else if (exe && looksUserWritablePath(exe)) {
      if (!seenExe.has(exe)) {
        seenExe.add(exe);
        steps.sever.push(severRule(exe));
        steps.disable.push(...disableMoves(exe));
      }
    } else if (exe) {
      unresolved.push({
        layer: "purge", source, subject, target,
        why: "the autostart lives in this mechanism, but the program it starts is not in a user-writable place -- a temp copy may be the actual payload, and this list does not guess which",
        how_to_find_out: `sc.exe qc "${subject}"  or  schtasks.exe /Query /TN "${subject}" /V /FO LIST`,
      });
    } else {
      unresolved.push({
        layer: "sever", source, subject, target,
        why: "the recorded command names a path that is not an executable -- a shortcut, a directory, or a launcher. Blocking or renaming it would be nonsense, and the file it finally starts is one resolution away",
        how_to_find_out: /\.lnk$/i.test(target)
          ? `resolve the shortcut first: (New-Object -ComObject WScript.Shell).CreateShortcut("${target}").TargetPath`
          : `read the full command with: reg query "${subject}" /v <name>  (for a Run key), or sc.exe qc "${subject}" (for a service)`,
      });
    }

    const recipe = PURGE_BY_SOURCE[source];
    if (recipe) {
      steps.purge.push({
        layer: "purge",
        target: subject || target,
        action: `Remove the ${recipe.what} that would start it again.`,
        command: recipe.command(subject || target),
        why: "an entry that survives is an entry that restores the program after everything above was done",
        cost: recipe.cost,
        reversible: recipe.reversible,
      });
    } else {
      unresolved.push({
        layer: "purge", source, subject, target,
        why: "this mechanism has no generic removal written down here; removing it by hand risks taking out a legitimate entry beside it",
        how_to_find_out: "read the mechanism's own listing before deleting anything from it",
      });
    }
  }

  // --- the credentials: revoke ----------------------------------------------
  // Delegated rather than re-implemented: the three readable formats and their fields are stated
  // once, in revoke.mjs, and a second copy here would be a second place for them to drift.
  const credentials = revokePlan(sessionHits, io);
  for (const site of credentials.sites) {
    steps.revoke.push({
      layer: "revoke", target: site.host,
      action: `End every session this host holds on the strength of the files in this list.`,
      command: `sign out of every device on https://${site.host}/ , then change the password and revoke issued tokens`,
      why: "a token carried away in a cookie jar keeps working after the jar is deleted -- this is the only step that reaches the other side",
      cost: "every device that used the same password has to sign in again",
      sources: site.sources,
      reversible: false,
    });
  }

  // --- the order, derived rather than fixed --------------------------------
  const selfRestoring = steps.purge.length > 0 || steps.disable.length > 0;
  const order = selfRestoring ? ["sever", "disable", "purge", "revoke"] : ["revoke", "purge", "sever", "disable"];
  const whyThisOrder = selfRestoring
    ? "Something here is recorded as starting itself, so the moves run outward-in: cut the connection, stop it starting, remove what would bring it back, and only then end what it stole. Doing revoke first would be fine for the credential but pointless for the program, which is still running."
    : "Nothing here is recorded as restarting itself, so the credential step comes first: once the file is deleted the list of hosts it unlocked cannot be recomputed, and a revocation list is the one thing on this page that cannot be reconstructed later.";

  const empty = NEUTRALIZE_LAYERS.filter((l) => steps[l].length === 0);
  return {
    steps, order, whyThisOrder, unresolved, emptyLayers: empty,
    readable: credentials.readable, notReadable: credentials.notReadable,
  };
}

/** What a neutralisation list is not. Attached to every response. */
export const NEUTRALIZE_NOT_CLAIMED = [
  "That anything on this list was carried out. This tool executes nothing -- no process, no registry write, no firewall rule, no account operation.",
  "That the order is right for every threat. It is derived from the evidence at hand: a recorded autostart means the item can restore itself, and that is the only self-restoring signal a static reader has. An item that restores itself some other way is not detected here.",
  "That a blocked program is a contained one. The firewall rule stops the connection from this machine; it does not stop a copy elsewhere, and it does not stop a payload that was already delivered.",
  "That ending a session ends the intrusion. It ends the sessions these files carried. Whether the foothold remains is aikawamei_triage's question, and whether the files should go is aikawamei_clean's.",
];
