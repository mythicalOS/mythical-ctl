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

**What it means.** `~/.mythical/.state/ledger.staging` is present. A restore of installer state started
and did not finish committing.

**What the CLI will and will not do.** Every ordinary command refuses and names the staging file rather
than proceeding as if nothing were happening — a half-restored ledger is not a fresh install and not a
valid one either.

**Next command.** Resume or abandon the restore per the message `mythical-ctl` prints when it sees the
staging marker. Restore itself is data-movement machinery outside this page's scope (see
`lib/copy.sh`/`lib/migrate.sh`); this section exists so the state is recognisable when you meet it from
the repair side.

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
