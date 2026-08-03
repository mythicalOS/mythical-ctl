# Recovering a broken installation

This page is for the moment `mythical-ctl` has already told you something is wrong. Each section below
is one state the CLI can report: what it means, what `mythical-ctl` will and will not do about it on its
own, and the command that moves you forward. It is not a description of the code — see the comments in
`lib/repair.sh`, `lib/ledger.sh`, `lib/intent.sh` and `lib/netref.sh` for that.

The single idea underneath all of it: **`mythical-ctl` never guesses**. When it cannot prove a fact — is
this object mine, is this the network I meant, has this intent's object actually appeared — it stops and
tells you what it cannot prove, rather than picking the answer that is usually right. Every section below
follows from that.

## A corrupt ledger

**What it means.** `~/.mythical/.state/ledger` exists but its checksum does not match its contents, its
schema line is malformed, or it is not newline-terminated. Something wrote to it, or truncated it,
outside `mythical-ctl` itself.

**What the CLI will and will not do.** Every command that reads the ledger refuses, including the ones
that only report — `status` refuses exactly as `install` does. A corrupt ledger is the one authority for
"which objects are mine", so nothing is deleted and nothing is adopted on a guess: **a corrupt ledger
costs you your rollback protection, not your containers.** Your running products keep running; `docker
ps` still shows them. What you lose until you repair is the ability to safely start, stop, recreate or
uninstall anything, because none of those can prove which objects belong to this installation.

**Next command.** `mythical-ctl state repair`. It re-derives an installation identity from the labels
already on your containers, volumes and networks, then rebuilds provenance from what it finds. Read
["Choosing which installation repair rebuilds"](#choosing-which-installation-repair-rebuilds) below before
you run it with more than one product on the daemon.

## A ledger newer than this CLI

**What it means.** The ledger's schema version is higher than this build of `mythical-ctl` understands —
an older `mythical-ctl` binary was pointed at a home directory a newer one already wrote to.

**What the CLI will and will not do.** Refuses outright, naming the schema version it found and the one
it supports. This is not a repair case: an old binary that pressed on with a schema it does not fully
understand would misread fields it has never seen and could delete objects it misidentifies. There is no
guarantee to lose here, because nothing is touched.

**Next command.** Install the current `mythical-ctl` release and re-run whatever you were doing.

## No ledger, but existing state

**What it means.** `~/.mythical/.state/ledger` is absent, but something else says this is not a fresh
machine anyway — a `<product>.conf`, a per-product directory, or a runtime object carrying a mythicalOS
installation label. A genuinely fresh install has none of these; a restore that carried the rest of
`~/.mythical/` without the ledger, or one that dropped just the ledger file, looks exactly like this.

**What the CLI will and will not do.** Refuses to treat the machine as a first install. Minting a fresh
identity here would leave the pre-existing state — and any labelled objects already on the daemon —
unaccounted for, which is the same "which of these is mine?" problem a corrupt ledger leaves, arrived at
from the other direction.

**Next command.** `mythical-ctl state repair`. If there truly are no labelled runtime objects on the
daemon (the pre-existing state was only host files), repair offers a confirmed reinitialization instead
of deadlocking on it — see the zero-candidates row below.

## An in-progress restore

**What it means.** `~/.mythical/.state/ledger.staging` is present. A `mythical-ctl restore` started and
did not finish committing.

**What the CLI will and will not do.** Every ordinary command refuses and names the staging file rather
than proceeding as if nothing were happening — a half-restored ledger is not a fresh install and not a
valid one either. This is deliberate: the staging ledger is NEVER authoritative (§6c/D59) — nothing
launches, deletes or reconciles from it, only from the real ledger a restore activates at its very last
step.

**Next command.** Run `mythical-ctl restore <backup-directory>` again to resume, or `mythical-ctl restore
--abandon` to give up on it. See "A restore stuck at a phase" below for what each recorded state means and
what each command does about it.

## A retained network intent

**What it means.** `mythical-ctl` recorded that it was about to create a network (write-ahead intent,
§6b) and has not yet been able to confirm the object exists. Networks are never silently reissued
(D38: unlike a volume, a duplicate-name network create can succeed and leave two networks with the same
name and the same nonce), so the intent sits open until it is either reconciled against a real object or
explicitly abandoned.

**What the CLI will and will not do.** It waits. `mythical-ctl` cannot tell "the daemon never received the
create" from "the daemon accepted it and has not finished", so it will not clear the intent on its own —
doing so could later collide with the object actually appearing. A retained intent does not by itself
block ordinary use of other products.

**Next command.** `mythical-ctl state abandon-intent network <name>`. This is refused until the intent is
older than `MI_INTENT_GRACE` seconds (five minutes by default) — the delay makes a delayed arrival from
the daemon less likely, though it cannot prove one will never come — and it always asks for confirmation.
Abandoning does **not** guarantee the object will never appear: if it does later, the next mutating
command stops and reports it as an unrecorded same-identity object (below) rather than adopting it
silently.

## An unrecorded same-identity object

**What it means. What guarantee is lost.** A container, volume or network is labelled with **this**
installation's identity, and the ledger has no record of it. This is the state that most directly costs
you something: it is yours, by its own label, and the ledger — the one place deletion authority comes
from — does not know it exists. Nothing else in this list is ambiguous about ownership; this one is
ambiguous about the record.

**What the CLI will and will not do.** Every mutating command stops before touching anything. It is never
adopted silently (that would let a stale intent's object, or a create confirmed after a `state repair`
snapshot, quietly become authoritative) and never deleted automatically (that is exactly the
misidentification protection labels and nonces exist to prevent).

**Next command.** `mythical-ctl state repair`, choosing this identity — it rebuilds the missing
provenance from the object's own labels. If you know precisely how the object got here and repair is not
appropriate, remove or reconcile it with the container runtime directly.

## An unattributed object on a shared daemon

**What it means.** A container, volume or network carries a mythicalOS installation label, but for a
**different** identity than this installation's. On a daemon shared by more than one user or more than
one installation (§4b.4), this is the ordinary case, not a fault.

**What the CLI will and will not do.** Reports it and leaves it exactly alone — never adopted, never
removed, never even proposed for removal. There is no guarantee lost here: the object was never yours to
begin with, and nothing about this installation's own state changes.

**Next command.** None, usually. If you believe it is actually stale (an old installation nobody uses
any more), that is a decision for whoever owns that identity, made with the container runtime directly —
`mythical-ctl` will not make it for you.

## A failed live verification

**What it means.** A container is running and something the installer recorded as owed — its family DNS
alias resolving on the network it is attached to — did not check out when actually asked. This can be
transient (the network is still settling) or real (something moved the container to a different network
out of band, or its DNS mechanism is broken).

**What the CLI will and will not do.** The container is left running. The check stays recorded as
outstanding rather than being cleared on a check that did not pass — clearing it would tell every sibling
product this one is reachable when it might not be. Nothing is stopped or restarted on your behalf.

**Next command.** Investigate why the alias did not resolve — most often with the container runtime
directly, or by re-running the product's `start`, which repeats the check. If the underlying installer
state was rebuilt by a `state repair`, a second `state repair` (or the product's next explicit start) is
the outstanding check's next chance to clear.

## A network migration stuck at a phase

**What it means.** `mythical-ctl net rebind` moves the whole family from one network to another in six
recorded phases (D45), each one only entered once the previous phase's proof is on disk, so that no phase
ever leaves the family split across two networks with no record of it. If the process was interrupted —
crashed, killed, or the daemon went away mid-phase — the ledger still names the phase it last completed.

**What the CLI will and will not do — by phase:**

| Recorded phase | What has happened | What has not |
|---|---|---|
| 1 | The migration intent is recorded: source, target, and the container set it applies to. | No container has been touched yet. |
| 2 | Every container in the set is connected to the target network, at a lower gateway priority than the source. | The source is still the preferred route; nothing has been verified there yet. |
| 3 | Every container's alias has been verified as resolving correctly on the target, and egress through the source is still confirmed working. | The source is still attached to everything — nothing has been detached. |
| 4 | The source network has been detached from containers whose target attachment was individually re-confirmed first. | The reference (which network the family is on) has not been updated yet. |
| 5 | Final topology has been verified: every container is on the target alone, with alias resolution and egress confirmed there. | The intent has not been cleared — this phase exists precisely so it is safe to clear next. |
| 6 | The network reference is committed to the target and the migration intent is cleared. | — the migration is complete. |

No phase leaves the family partitioned: at every recorded phase, either every container in the set is
still on the source, or it has been proven to be on the target before the source is ever removed. The
migration never unwinds — being attached to both networks at once is a bounded, recorded, safe
intermediate state, and being attached to neither is not, so there is nothing to roll back to that is
safer than continuing forward.

**Next command.** `mythical-ctl net rebind` again. It reads the recorded phase and resumes forward from
there; you do not need to know which phase it stopped at.

## A stranded object after a repair

**What it means. What guarantee is lost.** `state repair` snapshots the runtime once, rebuilds the ledger
from that snapshot, and commits. The family lock excludes every other `mythical-ctl` process while it
runs — but it cannot exclude the container runtime's daemon itself. If the daemon was still completing a
create that a now-dead client had already issued, that object can appear **after** the snapshot and be
absent from the freshly rebuilt ledger.

This is the one gap `state repair` states plainly rather than silently closes: **it cannot prove nothing
is in flight.** Ordinary reconciliation cannot rescue such an object afterward, either — rebuilding the
ledger discarded the write-ahead intent it would have matched against, and a zero-candidate
reinitialization mints a brand-new identity that an object labelled with the old one can never match.

**What the CLI will and will not do.** Nothing automatic. The object shows up in `status` as unattributed
or as an unrecorded same-identity object, depending on which identity ended up on the rebuilt ledger.
Adopting it back in is deliberately not automated: getting that wrong is how one installation adopts
another user's containers.

**Next command.** There is no dedicated recovery verb for this yet. Reconcile it with the container
runtime directly — inspect its labels to see which installation it claims, and act accordingly.

---

## A storage migration stuck at a phase

**What it means.** `mythical-ctl migrate-storage` moves one product's data from a named volume to a host
directory in nine recorded phases (§5/§5.2), each recorded *before* its own action runs, so a crash
mid-phase leaves the ledger naming the phase that was in progress rather than the last one that
finished. If the process was interrupted, resuming re-derives the true state from what is actually on
disk rather than trusting the recorded phase blindly (phase 6 onward is only trusted once the
destination is confirmed to carry phase 5's own recorded identity; otherwise resume falls back to phase
5, whose own resolve-and-recover logic — retry the rename from staging, or proceed with an empty
destination when there was nothing yet to protect — takes it from there).

**Next command.** `mythical-ctl migrate-storage <product> <role> --to-bind <path>` again, with the SAME
destination. It reads the recorded intent and resumes; you do not need to know which phase it stopped
at. This is never automatic — it asks for confirmation before doing anything destructive, exactly as a
fresh migration does.

### The security posture: a safe location, not a race won

Both trees a migration touches — the source volume's contents and the destination host tree — are
untrusted by this command's own design (§5.1). Bash has no `openat`/`renameat`/`unlinkat`-style
operation that stays bound to an already-open directory handle, so **every** filesystem check this
command makes resolves a path NAME, and between that check and whatever uses the result, anyone who can
also write the same parent directory can rename or replace what the name refers to. A re-check
immediately before each use narrows that window; it cannot close it — there is no operation in this
shell that is atomic with a check made a moment earlier against a name neither side of the check
controls exclusively.

What **is** achievable in bash is refusing to operate in a location where that premise holds in the
first place. Before touching anything, `migrate-storage` requires the destination's parent directory to
be owned by the operator running it and writable by no one else (not the group, not everyone) — reject
`chmod 700 that-directory` and the command refuses outright, naming the mode it found. If no one besides
this process can write the parent, there is no party left to run the race, regardless of how wide any
individual window is. This is why the fix for a "someone tampered with the destination mid-migration"
report is not a retry with more logging — it's `chmod 700` on the destination's parent, then retry.

Reclaiming a leftover staging directory (a `.mythical-staging-<nonce>` sibling of a destination, left
behind by an interrupted attempt) follows the same principle rather than a re-check: after its identity
is verified against the recorded intent, it is renamed into `~/.mythical/.state/reclaim` (mode 700, this
installer's own, never a sibling of the untrusted destination) *before* being deleted, and re-verified
there. An attacker who cannot write into that directory cannot swap what the rename is about to delete —
the same access-control argument as the parent check above, applied to the one place this command
recursively removes something by name. If the staging directory and `~/.mythical/.state/reclaim` are on
different filesystems, reclaim refuses rather than fall back to a non-atomic cross-device move (which
would silently reintroduce exactly the delete-by-untrusted-name pattern this exists to avoid) — the
leftover is reported and left in place for you to remove by hand.

### The one residual this cannot close, and why

Even with a trusted parent, the copy step itself must grant the product's own runtime uid write access
to the staging tree while it is populating it (§4.5 — every file's ownership and default ACL entries are
set as part of the copy, for the product to be able to use its data once migrated). That access is real,
host-level, and legitimate for the copy's duration. In the narrow window between phase 4's verification
finishing and phase 5's atomic commit, something already running as that exact runtime uid — not a
generic attacker, and not reachable at all once the parent-trust check above passes, but specifically a
process that already holds the same uid the product's own container ran as before this migration stopped
it — could in principle plant a symlink inside the staging tree that escapes it.

This is mitigated, not eliminated: immediately before the commit, `migrate-storage` re-walks the entire
staged tree host-side (following no symlink it encounters, the same discipline the copy step's own walk
uses) and refuses if any symlink's target escapes the tree — the same rule the copy step itself already
enforces, reused rather than re-implemented, so there is exactly one definition of "escapes" in this
codebase. This shrinks the window from "the whole gap between phase 4 and phase 5" down to "the time of
this one host-side walk", which is the smallest window bash can produce without a kernel primitive this
shell does not have. It is not zero. Closing it fully would mean the copy step never grants the runtime
uid write access until after the atomic commit — which the copy contract does not support today, since
per-file ownership is applied *as* each file is copied, not in a separate pass afterward.

**What this means for you:** the residual is only reachable by something already running as the exact
uid the product's container used, on the same host, in the seconds between phase 4 and phase 5, if it
already knows the staging directory's path (an unguessable, per-attempt nonce). It is not reachable by
an unrelated process, and it is not reachable at all if the destination's parent fails the trust check
above. If you operate on a host where the product's runtime uid could plausibly correspond to another
live process (a shared, multi-tenant host), treat that as the boundary this residual does not defend
across.

---

## A restore stuck at a phase

**What it means.** `mythical-ctl restore <backup-directory>` moves a backup's ledger and named volumes
back onto a machine in six recorded phases (§6c/D59), the first of which — writing the incoming ledger to
`.state/ledger.staging`, with the restore's own intent inside it — happens before anything is created. If
the process was interrupted, the staging ledger still names the state it last reached; `mythical-ctl
restore` (with the same backup directory) reads it and resumes.

**What the CLI will and will not do — by phase:**

| Recorded phase | What has happened | What has not |
|---|---|---|
| 1 | The incoming ledger is staged, with the restore's own intent recorded inside it. | No volume has been touched yet; there is no active ledger. |
| 2 | Per volume: created WITH the recorded nonce label, then re-inspected. A same-name volume that does not carry that nonce is a SURVIVOR — restore refuses, naming it, rather than filling a volume it cannot prove it just created. | The volume has not been filled. |
| 3 | The volume is filled from the backup's own contents, through the pinned copy container. | Nothing has been verified yet. |
| 4 | The filled volume is verified against the backup's own per-entry manifest — type, link targets, hardlink topology, mode, ownership and mtime, not bytes alone. A symlink recreated as a plain file, or a hardlink group flattened into independent copies, is caught here even though both can digest identically. | The staging ledger still carries the restore's intent. |
| 5 | Once EVERY volume verifies, the staging ledger is atomically rewritten to its intent-free form. | The staging ledger has not been activated — it is still not the active ledger. |
| 6 | The staging ledger is renamed into the real ledger path. | — the restore is complete; the installation is live again. |

Resuming does not trust the recorded phase blindly for the per-volume work (phases 2–4): a volume that
already carries the recorded nonce but is not empty is not automatically treated as a stranger's leftover
— it is re-verified against the backup's manifest first, and only refused as a genuine partial fill if
that check does not pass. This is what lets a crash while filling the *second* of several volumes resume
cleanly, having already verified the first.

**Next command.** `mythical-ctl restore <same-backup-directory>` again. It reads the recorded phase from
the staging ledger and resumes forward from there — you do not need to know which phase it stopped at.

### Trusting a backup: the honest boundary

`mythical-ctl backup` and `restore` checksum everything — the ledger, and every volume's contents and
per-entry manifest — but a checksum only proves the bytes have not changed since whoever last wrote
them; it says nothing about who that was. There is no secret in this installer to sign a backup with,
so a party who can **write** the backup tree can replace a volume's contents and its manifest with a
mutually consistent pair, and recompute the ledger's own checksum right along with them — restore would
accept and activate all of it, because internal consistency is exactly what a checksum can prove.

What stands in for a signature is **location**. Both `backup`'s output directory and `restore`'s input
directory must resolve (symlinks followed, not merely their parent) to a location that only the
operator (or root) can write to — not a directory anyone else on the machine has group or other write
access to, anywhere in its ancestor chain. If no other party can write into the backup root, no other
party can forge what is inside it, mutually consistent or not — the same "authenticate by location, not
by out-racing a hostile writer" principle `migrate-storage`'s own destination check applies (see "The
security posture: a safe location, not a race won", above), stated here as **backup's entire trust
model**, not a residual on top of a stronger one.

**What this means for you:** keep backups on storage only you (or root) can write to — your own home
directory, an operator-owned external volume, anything with a `700`/`750`-or-tighter chain from `/` down
to the backup directory itself. A backup sitting in a world-writable location (a shared `/tmp`, a
group-writable NFS mount everyone on the box can write to) is not authenticated by its checksums alone,
and `restore` refuses it outright rather than trusting bytes it cannot vouch for the origin of.

**Refused outright, never merged:** restore while an ACTIVE ledger is present. Restore is a recovery
operation for a machine with no live installation, not a replacement for one — activating a restored
ledger over a live one would orphan every running container of the installation that is here now, with
its provenance gone in the same atomic rename. Uninstall the current installation first.

**A corrupt staging ledger authorizes no cleanup.** If `.state/ledger.staging` exists but does not
validate, its own checksum is exactly what says not to trust the record of which partial volumes a
previous attempt created. It is preserved aside (named in the refusal) rather than read, and any partial
volumes from that attempt are left in place, blocking a fresh restore, until you remove them yourself —
the installer cannot prove they are its own from a ledger it just refused to read.

**Next command (abandon).** `mythical-ctl restore --abandon`. Volumes the abandoned attempt created —
matching the EXACT name and nonce it recorded — are removed FIRST, under their own recorded identity;
only once that is done is the staging ledger itself deleted. A volume carrying a *different* nonce than
recorded is preserved and reported rather than guessed at. This ordering is deliberate: the staging
ledger is the only record proving which volumes belong to this attempt, so destroying it before the
volumes it names would leave them as unrecorded survivors the next restore refuses to fill over, with
nothing left to authorize their removal either.

## Choosing which installation repair rebuilds

`state repair` looks at every container, volume and network's own installation label — never the ledger
it is about to rebuild — and asks which distinct identities are present.

- **Zero candidates.** Nothing on the daemon carries a mythicalOS label at all. Repair offers a confirmed
  reinitialization: a brand-new identity is minted and the ledger is rebuilt from nothing. This resets
  every trust floor (see below) and will never recognise any object that turns up later carrying an
  older identity — such an object is reported as unattributed, never adopted.
- **Exactly one candidate.** Still shown, and still requires you to name it explicitly
  (`mythical-ctl state repair <identity>`) — it is never adopted just because it is the only one
  visible. On a daemon another user might also use, silently adopting the sole candidate is how you end
  up with authority over someone else's containers.
- **More than one candidate.** All of them are listed, with their objects, so you can tell which is
  yours. Nothing is touched until you choose one. `--reinitialize` is refused outright whenever any
  candidate exists — the answer is to choose one of them, not strand their objects behind a fresh
  identity.

Once you name an identity, repair states what it can and cannot do before it asks for a final
confirmation:

- **Recovered:** provenance for every container, volume and network labelled with that identity.
- **Reset — a real rollback window:** every trust floor. Floors are a record of history, not something
  the runtime carries, so repair cannot reconstruct them; a withdrawn manifest version could be replayed
  and accepted again until new floors are established by normal use. (The trust *anchor* — which family
  index this installation has authenticated — is not part of this: it is preserved, so repair does not
  force you back online to re-establish it.)
- **Inferred, not recovered:** desired state, from what each container is observed to be doing right now.
  A stopped container stays recorded as stopped; repair cannot know whether that was deliberate.
- **Never rebuilt, never enumerated:** image provenance. Images carry no installation label at all
  (D37), so repair neither claims to know which images were pulled by this installer nor deletes any —
  that list lived only in the ledger being repaired.

Any container repair finds already running is live-verified in the same run — see "A failed live
verification" above for what happens if that check does not pass.
