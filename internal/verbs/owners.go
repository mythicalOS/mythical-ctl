package verbs

// THE WAVE 5 OWNER MAP. The test beside it is its guard.
//
// tests/unit/verbs.bats and tests/acceptance/lifecycle.bats each hold behaviour owned by more than
// one task, so neither file can be named whole as one task's spec source: an inventory claiming a
// whole file would be unsatisfiable until the last task landed, and the tempting thing to do at
// that point is to quietly weaken the claim. The partition below is therefore written down BEFORE
// the first line of the wave, so no task can widen or narrow its own share after seeing how hard
// its share is, and so the wave audit has exactly one owner to check each bats test against.
//
// THE RULE THAT DREW IT: a test is owned by the LAST task to land among the verbs it actually
// invokes. Task 22 lands install/start/stop/restart/recreate/batch; Task 23 adds status and
// uninstall; Task 24 adds repair/state/net. Owning a test any earlier would force its port to
// assert less than the bats test does — the exact defect the Wave 4 gate caught twice — because the
// verb the assertion reads through would not exist yet.
//
// One refinement the rule needs: mi_verb_status is called two ways in verbs.bats. Where its OUTPUT
// is asserted it is the subject, and the test is Task 23's. Where it is called with its output
// discarded it is being used to refresh observed state, which Task 22 reaches directly through the
// state seam — so such a test stays with the verb it is actually about (test 11, the stop-ordering
// test, is the only one of these, and it is a stop test, not a status test).
//
// Task 24 owns NO test in either shared file: every repair/state/net test lives in
// tests/unit/repair.bats, which it owns whole. That empty share is deliberate, and it is recorded
// here so the audit reads it as a decision rather than as an omission.
//
// Shares: Task 22 = 50, Task 23 = 47, Task 24 = 47. Total 144, which is every test in all three
// files, each claimed once. TestOwnerMapPartitionsBats proves that, in both directions, against the
// bats files themselves rather than against these comments.

// batsTest identifies one bats test: the file that defines it, and its exact name.
type batsTest struct {
	File string
	Name string
}

// batsOwner maps a bats test to the Wave 5 task that ports it. A task's Go inventory may claim only
// its own entries here.
var batsOwner = map[batsTest]int{

	// ---- tests/unit/verbs.bats ----
	{"tests/unit/verbs.bats", "install converges: identity, membership, network, volume, container, running, verified"}:                     22,
	{"tests/unit/verbs.bats", "install is idempotent — a re-install leaves user-owned files byte-identical"}:                                22,
	{"tests/unit/verbs.bats", "install always declares running — re-installing a stopped product brings it back up (§6b.3)"}:                22,
	{"tests/unit/verbs.bats", "install called as a library returns usage (2) on a value-less --image, never loops forever"}:                 22,
	{"tests/unit/verbs.bats", "installing a SECOND product leaves the first's config and data untouched"}:                                   22,
	{"tests/unit/verbs.bats", "a NOT-LAUNCHED manifest prints the message, exits 3, and creates NO product state"}:                          22,
	{"tests/unit/verbs.bats", "a not-launched attempt attempts NO PULL AT ALL"}:                                                             22,
	{"tests/unit/verbs.bats", "a not-launched attempt DOES record the trust floor — otherwise a stale manifest replays later"}:              22,
	{"tests/unit/verbs.bats", "a LAUNCHED manifest whose image is not found is a LOUD RELEASE ERROR, never the not-launched message"}:       22,
	{"tests/unit/verbs.bats", "auth and network pull failures are loud and distinguishable"}:                                                22,
	{"tests/unit/verbs.bats", "stop sets desired=stopped BEFORE stopping, and a later run leaves it stopped"}:                               22,
	{"tests/unit/verbs.bats", "stop FAILS (1) when the runtime stop did not happen — a swallowed failure is not success"}:                   22,
	{"tests/unit/verbs.bats", "install does NOT pull when the image-presence check could not be asked (rc1 is not absence)"}:                22,
	{"tests/unit/verbs.bats", "restart is REFUSED on a stopped product rather than silently starting it"}:                                   22,
	{"tests/unit/verbs.bats", "restart FAILS (1) on a swallowed stop — a container that never went down is not a restart"}:                  22,
	{"tests/unit/verbs.bats", "recreate of a STOPPED product stays stopped"}:                                                                22,
	{"tests/unit/verbs.bats", "recreate live-verifies like a fresh install, not assumed good for replacing a working one"}:                  22,
	{"tests/unit/verbs.bats", "the host-tool slot survives the whole lifecycle, byte-identical and mode-unchanged"}:                         23,
	{"tests/unit/verbs.bats", "no verb ever creates a host-tool slot for a product that has none"}:                                          23,
	{"tests/unit/verbs.bats", "product uninstall RETAINS the trust floor and membership (§6c) — the rollback bypass"}:                       23,
	{"tests/unit/verbs.bats", "product uninstall leaves bin/ and mythical.conf, and a sibling's config, alone"}:                             23,
	{"tests/unit/verbs.bats", "product uninstall RETAINS named volumes, and keeps their provenance so --purge still has authority"}:         23,
	{"tests/unit/verbs.bats", "--purge removes the volumes it has authority over and tombstones them"}:                                      23,
	{"tests/unit/verbs.bats", "NO verb removes an image — not uninstall, not --purge"}:                                                      23,
	{"tests/unit/verbs.bats", "--purge OFFERS images as an explicitly confirmed extra step, naming the shared-use risk"}:                    23,
	{"tests/unit/verbs.bats", "uninstall with an --image override leaves the override image in place"}:                                      23,
	{"tests/unit/verbs.bats", "status REPORTS volumes — it used to filter them out of the ledger loop entirely"}:                            23,
	{"tests/unit/verbs.bats", "status scopes volumes to the named product, like it already scoped containers"}:                              23,
	{"tests/unit/verbs.bats", "status distinguishes a volume that is RECORDED but gone from one that is present"}:                           23,
	{"tests/unit/verbs.bats", "a role declared precious is RECORDED as such on the volume, and reported UNREGENERABLE"}:                     23,
	{"tests/unit/verbs.bats", "a volume record with NO precious field reads as UNREGENERABLE, never as safe to delete"}:                     23,
	{"tests/unit/verbs.bats", "the purge warning separates unrecoverable volumes from regenerable ones, and names both"}:                    23,
	{"tests/unit/verbs.bats", "product uninstall --purge REFUSES without confirmation, and removes NOTHING"}:                                23,
	{"tests/unit/verbs.bats", "MI_CONFIRM=no refuses a product purge just as it refuses a family one"}:                                      23,
	{"tests/unit/verbs.bats", "a plain product uninstall does NOT prompt — the prompt stays meaningful"}:                                    23,
	{"tests/unit/verbs.bats", "an ADOPTED volume keeps its product, role and data class — so --purge still finds it"}:                       22,
	{"tests/unit/verbs.bats", "FAMILY uninstall resets the ledger entirely WITHOUT --purge, and leaves the volumes (§6c)"}:                  23,
	{"tests/unit/verbs.bats", "family uninstall keeps named volumes without --purge and removes them with it"}:                              23,
	{"tests/unit/verbs.bats", "family uninstall --purge removes the volumes it has authority over"}:                                         23,
	{"tests/unit/verbs.bats", "family uninstall removes the network it created"}:                                                            23,
	{"tests/unit/verbs.bats", "family uninstall NEVER removes an operator-supplied network — it is attach-only"}:                            23,
	{"tests/unit/verbs.bats", "family uninstall PRESERVES an object whose nonce no longer matches"}:                                         23,
	{"tests/unit/verbs.bats", "family uninstall removes NO image, and says so"}:                                                             23,
	{"tests/unit/verbs.bats", "family uninstall refuses without an explicit confirmation, and changes nothing"}:                             23,
	{"tests/unit/verbs.bats", "an unrecorded same-identity object STOPS a mutating verb"}:                                                   22,
	{"tests/unit/verbs.bats", "the same object does NOT stop status, which reports it and exits 0"}:                                         23,
	{"tests/unit/verbs.bats", "status lists unattributed objects and never proposes removing them"}:                                         23,
	{"tests/unit/verbs.bats", "an --image override is loud, recorded, and reported by status"}:                                              23,
	{"tests/unit/verbs.bats", "recreate PRESERVES an install-time --image override, so the running image and status agree (§13)"}:           23,
	{"tests/unit/verbs.bats", "the shared bootstrap-secret gate refuses a secret the policy no longer grants (install+recreate share it)"}:  22,
	{"tests/unit/verbs.bats", "--force-install is loud and reported by status"}:                                                             23,
	{"tests/unit/verbs.bats", "a manifest for a DIFFERENT product is refused before any object is created"}:                                 22,
	{"tests/unit/verbs.bats", "the family lock is held for the whole of a mutating verb, and released after"}:                               22,
	{"tests/unit/verbs.bats", "a verb refuses when the lock is already held by a live process"}:                                             22,
	{"tests/unit/verbs.bats", "recreate ENSURES the selected image before removing the container — an unpullable image preserves it"}:       22,
	{"tests/unit/verbs.bats", "status reports an UNREADABLE identity, not 'nothing installed' (rc 1 is not rc 3)"}:                          23,
	{"tests/unit/verbs.bats", "status reports an UNREADABLE operator network, not 'not created yet' (rc 1 is not rc 3)"}:                    23,
	{"tests/unit/verbs.bats", "a plain install CLEARS a prior --image override, so status reverts to the manifest image"}:                   23,
	{"tests/unit/verbs.bats", "a FAILED --image install records NO override, so a later plain install names none"}:                          23,
	{"tests/unit/verbs.bats", "status reports an UNREADABLE installer-owned network record, not 'not created yet' (rc 1 is not rc 3)"}:      23,
	{"tests/unit/verbs.bats", "status reports an UNREADABLE network-migration record, not silence (rc 1 is not rc 3)"}:                      23,
	{"tests/unit/verbs.bats", "a mutating verb STOPS when probe cleanup cannot complete — an unresolved probe is not stepped over"}:         22,
	{"tests/unit/verbs.bats", "family uninstall REFUSES and does NOT reset the ledger when the object listing is unreadable"}:               23,
	{"tests/unit/verbs.bats", "product uninstall --purge REFUSES on an unreadable object listing rather than silently skipping volumes"}:    23,
	{"tests/unit/verbs.bats", "install REFUSES to create a volume when its provenance record is unreadable (rc 1 is not rc 3)"}:             22,
	{"tests/unit/verbs.bats", "status reports an UNREADABLE object listing as UNREADABLE, never as an empty fleet (rc 1 is not rc 3)"}:      23,
	{"tests/unit/verbs.bats", "recreate NORMALIZES a context failure to operational failure (1), never a raw or undefined exit code"}:       22,
	{"tests/unit/verbs.bats", "install REFUSES to create a container when its provenance record is ambiguous (rc 1 fail-closed)"}:           22,
	{"tests/unit/verbs.bats", "a REFUSED install (unaccounted object) does NOT advance the anti-rollback trust floor"}:                      22,
	{"tests/unit/verbs.bats", "start reports an ambiguous container provenance as unreadable, never 'not installed' (rc 1 is not rc 3)"}:    22,
	{"tests/unit/verbs.bats", "family --purge does NOT reset the ledger when a volume record has no readable name (fail closed)"}:           23,
	{"tests/unit/verbs.bats", "start returns operational failure (1), never undefined 4, when the container needs a rebuild"}:               22,
	{"tests/unit/verbs.bats", "a FAILED forced install leaves no force-install record, so a later normal install is not falsely annotated"}: 23,
	{"tests/unit/verbs.bats", "family uninstall does NOT reset the ledger when the operator-network reference is unreadable"}:               23,
	{"tests/unit/verbs.bats", "start/stop/restart REFUSE a foreign container that reuses our name (nonce authority, not just a record)"}:    22,
	{"tests/unit/verbs.bats", "status reports an installer-owned network record with no id as UNREADABLE, not empty"}:                       23,
	{"tests/unit/verbs.bats", "status reports a container record with no name as UNREADABLE, never hiding it"}:                              23,
	{"tests/unit/verbs.bats", "a re-install whose container removal FAILS does not proceed to bring-up and restores the container"}:         22,
	{"tests/unit/verbs.bats", "a recreate whose container removal FAILS does not proceed to bring-up and restores the container"}:           22,
	{"tests/unit/verbs.bats", "recreate HONORS a recorded force-install on a still-not-launched manifest, rather than refusing it"}:         22,
	{"tests/unit/verbs.bats", "status reports a netmig record missing fields as UNREADABLE, not a blank migration"}:                         23,

	// ---- tests/acceptance/lifecycle.bats ----
	{"tests/acceptance/lifecycle.bats", "CLI: an unknown verb exits 2"}:                                                                        22,
	{"tests/acceptance/lifecycle.bats", "CLI: install with no product exits 2 and attempts nothing"}:                                           22,
	{"tests/acceptance/lifecycle.bats", "batch: all products succeed → 0"}:                                                                     22,
	{"tests/acceptance/lifecycle.bats", "batch: one succeeds, one not-launched → 3"}:                                                           22,
	{"tests/acceptance/lifecycle.bats", "batch: any failure → 1, even when another product installed fine"}:                                    22,
	{"tests/acceptance/lifecycle.bats", "batch: FAILING ONE PRODUCT MUST NOT ABORT THE OTHERS — the later product still installs"}:             22,
	{"tests/acceptance/lifecycle.bats", "batch reports per product"}:                                                                           22,
	{"tests/acceptance/lifecycle.bats", "a first-ever not-launched install mints NO identity or product state (§10a: no product state)"}:       22,
	{"tests/acceptance/lifecycle.bats", "CLI: a value-taking option with no value is a usage error (2), not an operational failure (1)"}:       22,
	{"tests/acceptance/lifecycle.bats", "an interrupted install converges on a re-run, with no half-state"}:                                    22,
	{"tests/acceptance/lifecycle.bats", "every published port binds 127.0.0.1 on the ACTUAL runtime object"}:                                   22,
	{"tests/acceptance/lifecycle.bats", "network mode host in mythical.conf is rejected"}:                                                      22,
	{"tests/acceptance/lifecycle.bats", "two concurrent installs are serialized under the family lock, with no lost state"}:                    22,
	{"tests/acceptance/lifecycle.bats", "CLI: install rejects --purge (an uninstall-only option) and installs nothing"}:                        22,
	{"tests/acceptance/lifecycle.bats", "CLI: start rejects --family (an uninstall-only option) even for a valid product"}:                     22,
	{"tests/acceptance/lifecycle.bats", "CLI: uninstall <product> --family is a usage error, not a silent family wipe that drops the product"}: 23,

	// ---- tests/unit/repair.bats ----
	{"tests/unit/repair.bats", "a NEWER ledger schema is refused, naming the required version (already Plan 1; asserted here)"}:          24,
	{"tests/unit/repair.bats", "a schema migration is a no-op at schema 1 and does not rewrite the ledger"}:                              24,
	{"tests/unit/repair.bats", "repair candidates are the DISTINCT installation identities present in object labels"}:                    24,
	{"tests/unit/repair.bats", "EXACTLY ONE candidate is still shown and still confirmed — never silently adopted"}:                      24,
	{"tests/unit/repair.bats", "two candidates: both shown, no action until one is chosen, the other's objects untouched"}:               24,
	{"tests/unit/repair.bats", "choosing an identity rebuilds provenance for containers, volumes and networks from labels"}:              24,
	{"tests/unit/repair.bats", "repair NEVER rebuilds image provenance and never claims to enumerate images"}:                            24,
	{"tests/unit/repair.bats", "outstanding checks are initialized to {alias} for EVERY recovered container"}:                            24,
	{"tests/unit/repair.bats", "a RUNNING recovered container is verified IN THE SAME REPAIR RUN"}:                                       24,
	{"tests/unit/repair.bats", "desired state is set from OBSERVATION and reported as inferred, listing each container"}:                 24,
	{"tests/unit/repair.bats", "trust floors are RESET, with the rollback window stated and confirmed"}:                                  24,
	{"tests/unit/repair.bats", "ZERO candidates offers confirmed REINITIALIZATION rather than deadlocking"}:                              24,
	{"tests/unit/repair.bats", "reinitialization is REFUSED when candidates were found — then the answer is to choose one"}:              24,
	{"tests/unit/repair.bats", "repair refuses while a LIVE lock is held"}:                                                               24,
	{"tests/unit/repair.bats", "repair states plainly that it cannot prove nothing is in flight"}:                                        24,
	{"tests/unit/repair.bats", "an object arriving AFTER a repair that RETAINED the identity is unrecorded same-identity"}:               24,
	{"tests/unit/repair.bats", "an object arriving after a REINITIALIZING repair is foreign-identity, listed, never touched"}:            24,
	{"tests/unit/repair.bats", "the non-owned reference is reconstructed from mythical.conf, not from the ledger"}:                       24,
	{"tests/unit/repair.bats", "reconstruction that finds a DIFFERENT network than the containers' stops and enters the migration"}:      24,
	{"tests/unit/repair.bats", "containers disagreeing about their network stops and reports — a migration cannot pick a side"}:          24,
	{"tests/unit/repair.bats", "abandon-intent refuses before the grace period and succeeds after, with confirmation"}:                   24,
	{"tests/unit/repair.bats", "abandon-intent will NOT run without confirmation"}:                                                       24,
	{"tests/unit/repair.bats", "candidate discovery FAILS CLOSED when an object's installation label cannot be read"}:                    24,
	{"tests/unit/repair.bats", "the post-reset rebuild loop FAILS CLOSED when an object's installation label cannot be read"}:            24,
	{"tests/unit/repair.bats", "network reconstruction FAILS CLOSED when a container's installation label cannot be read"}:               24,
	{"tests/unit/repair.bats", "'+none' is never recorded from an unread network-attachment state"}:                                      24,
	{"tests/unit/repair.bats", "net rebind FAILS CLOSED on an unreadable/ambiguous migration record instead of starting fresh"}:          24,
	{"tests/unit/repair.bats", "CLI: 'state repair <identity>' threads the chosen identity through to the library"}:                      24,
	{"tests/unit/repair.bats", "CLI: 'state abandon-intent <class> <name> <extra>' is a usage error, nothing attempted"}:                 24,
	{"tests/unit/repair.bats", "a ledger with a NEWER schema is refused by repair, never renamed aside as if corrupt"}:                   24,
	{"tests/unit/repair.bats", "candidate discovery keeps DISTINCT identities distinct even when one is a prefix of another"}:            24,
	{"tests/unit/repair.bats", "a repair-reconstructed network migration never records an empty fleet"}:                                  24,
	{"tests/unit/repair.bats", "CLI: 'net rebind <extra>' is a usage error, nothing done"}:                                               24,
	{"tests/unit/repair.bats", "containers that exist but share no attached network are NOT recorded as a clean reference"}:              24,
	{"tests/unit/repair.bats", "a real candidate is never treated as zero and silently reinitialized"}:                                   24,
	{"tests/unit/repair.bats", "a reconstructed migration's fleet list names EVERY container, never a truncated prefix"}:                 24,
	{"tests/unit/repair.bats", "adoption REFUSES an object whose nonce label is present-but-empty, never writes empty-nonce provenance"}: 24,
	{"tests/unit/repair.bats", "the PUBLIC verb rejects a surplus operand itself, at the library boundary, nothing attempted"}:           24,
	{"tests/unit/repair.bats", "an ambiguous or unusable trust anchor is dropped, not silently preserved, and the loss is named"}:        24,
	{"tests/unit/repair.bats", "net rebind's NEW-rebind branch normalizes a leaked rc 3 to operational failure 1"}:                       24,
	{"tests/unit/repair.bats", "live-verify FAILS CLOSED on a present-but-invalid product label, never clears from a fallback alias"}:    24,
	{"tests/unit/repair.bats", "the post-repair verify loop FAILS CLOSED on a container record with no readable name"}:                   24,
	{"tests/unit/repair.bats", "net rebind's RESUME branch respects MI_CONFIRM=no, exactly like a fresh rebind does"}:                    24,
	{"tests/unit/repair.bats", "a container attached to BOTH old and target networks is detected as mid-migration, not clean"}:           24,
	{"tests/unit/repair.bats", "a newline-bearing installation label is never split into forged candidates, nor adoptable"}:              24,
	{"tests/unit/repair.bats", "a transient/unreadable ledger read does not destroy it — repair fails closed, ledger intact"}:            24,
	{"tests/unit/repair.bats", "a GENUINELY corrupt ledger (checksum mismatch) still is destroyed, preserved aside, and rebuilt"}:        24,
}
