package enginetest

import (
	"fmt"
	"strings"
)

// HelperImage is the PINNED HELPER IMAGE'S CONTRACT, as a fixture — the port of the reference
// harness's `helperimg` (tests/harness/helperimg), which is itself the SPECIFICATION of what
// the real image must implement. It stands in for the copy container (D54/D58): a closed
// command word, flat `key=value` lines on stdout, and a status that is never the answer.
//
//	argv          <command> [<argument>...] — the command word FIRST, then its own arguments.
//	              An unsupported command word answers nothing and exits 2.
//	stdout        flat `key=value` lines, one per line, no nesting and no quoting.
//	exit status   0 the check ran and passed · 1 the check ran and FAILED · 2 the command word
//	              is not one this image implements. "The check failed" and "I could not run
//	              the check" are never the same answer.
//	fields        every key appears AT MOST ONCE, except the copy's own repeated vocabulary
//	              (entry/linktarget/stripped/mapped/refused/mismatch), where a second copy of
//	              the key is a second OBSERVATION rather than a contradiction.
//
// The commands, and what each observes:
//
//	preflight <dst> <ruid> <ouid>   EMPIRICAL, not inferred from the filesystem's name: create
//	                                a file, chown it, create a symlink, stat it back, set
//	                                DEFAULT ACL entries naming BOTH principals, then create a
//	                                child AS EACH uid and read it as the other.
//	                                  ownership= permissions= symlink= acl= inherit=
//	                                `acl=skipped` is legitimate ONLY when the two uids are
//	                                equal, where the step is genuinely a no-op. `inherit` is
//	                                the cross-read result.
//	copy <src> <dst> <ruid> <ouid> [--map-foreign]
//	                                /dst MUST BE EMPTY when this runs — the copy's own
//	                                precondition, checked HERE, on the writable mount,
//	                                atomically with the copy, never by a host-side glance that
//	                                races the mount and mangles untrusted names.
//	                                  entry=<type>:<path>   type ∈ file|dir|symlink|hardlink|special
//	                                  linktarget=<path><target>:<pathlen>   LENGTH-DELIMITED
//	                                  stripped=<path>:<bits>   mapped=<path>:<olduid>
//	                                  refused=<path>:<reason>  refused=<path>:foreign-uid:<uid>
//	                                  done=ok               printed ONLY on a completed copy
//	verify <src> <dst> <ruid> <ouid>
//	                                PER-ENTRY over that same contract, never a byte count:
//	                                  mismatch=<path>:type|digest|linktarget|mode|owner|mtime|hardlink|default-acl
//	                                  acl=ok|fail|skipped   checked=<n>   done=ok
//	acl <dst> <ruid> <ouid>         RESERVED: re-apply the dual-principal default entries
//	                                WITHOUT re-copying, for a repair path. The copy applies
//	                                them inline, so nothing calls this today.
//	access <dst>                    EFFECTIVE ACCESS, exercised rather than inferred — run
//	                                with `--user <runtime uid>`, so it answers as the product
//	                                would: traverse, read, write a probe file and remove it.
//	                                  traverse=ok  read=ok  write=ok
//
// THE FIELD SHAPES ARE PARSED, so their layout is part of the contract, and each two-part one
// puts its FIXED-SHAPE component where a path's own bytes cannot reach it: `entry=` puts the
// TYPE first (a path may legally contain a colon), `refused=` puts the REASON last, and
// `linktarget=` is length-delimited because BOTH the path and the target may contain colons.
//
// THE RESTORE-SIDE `verify` MODES ARE NOT HERE. The reference contract also defines three
// read-only modes of the same `verify` command word — `verify <src> --manifest`,
// `--count` and `--against-stdin` — distinguished by their SECOND argument, which can never be
// the literal `/dst` every ordinary caller passes. They belong to the backup/restore port and
// are added by it, with the fixtures its own tests pin; a mode invented here without those
// tests would be a shape nothing measures. Until then this fixture answers them with the
// contract's own "not implemented" status (2) rather than pretending.
type HelperImage struct {
	// Preflight, Copy, Verify, Access and ACL are the reference's HELPER_* knobs: they make
	// the image state a particular finding without a real daemon. "" means the conforming
	// answer ("ok").
	Preflight string
	Copy      string
	Verify    string
	Access    string
	ACL       string
	// Exit0 is the reference's HELPER_EXIT0: AN EXIT STATUS IS NOT A RESULT. With it set the
	// image states exactly the findings it otherwise would and then exits 0 anyway — the
	// regression a caller must survive by reading the STATED result rather than the status
	// beside it. Every arm below ends through fin(), so no arm can be the one still pinned
	// only by its status.
	Exit0 bool
}

// Entry is the HelperEntryFunc the Fake drives. It ignores the network views: every command
// here runs in the copy container's private (`none`) mode, where there is no resolver at all.
func (h *HelperImage) Entry(cmd string, args []string, _ HelperNetView, _ []byte) (int, []byte) {
	switch cmd {
	case "preflight":
		return h.preflight(args)
	case "copy":
		return h.copy(args)
	case "verify":
		return h.verify(args)
	case "acl":
		return h.acl(args)
	case "access":
		return h.access(args)
	}
	return 2, nil
}

// fin: with Exit0 set the findings stand and the status does not.
func (h *HelperImage) fin(code int, out string) (int, []byte) {
	if h.Exit0 {
		code = 0
	}
	return code, []byte(out)
}

func knob(v string) string {
	if v == "" {
		return "ok"
	}
	return v
}

// emitLinktarget writes one `linktarget=` line in the LENGTH-DELIMITED contract shape:
// `<path><target>:<pathlen>`, where <pathlen> is the path's BYTE length. The path and the
// target are concatenated with no separator; the trailing colon-free length tells the caller
// where the path ends, so a colon inside EITHER no longer breaks the split.
func emitLinktarget(path, target string) string {
	return fmt.Sprintf("linktarget=%s%s:%d\n", path, target, len(path))
}

func (h *HelperImage) preflight(args []string) (int, []byte) {
	if len(args) < 3 || args[0] == "" || args[1] == "" || args[2] == "" {
		return 1, nil
	}
	dst, ruid, ouid := args[0], args[1], args[2]
	k := knob(h.Preflight)
	// `silent`: the image ran, exited 0 and said nothing. A knob rather than an accident,
	// because the CALLER's handling of it is the property under test — an absent observation
	// is a refusal, not a pass.
	if k == "silent" {
		return 0, nil
	}
	own, perm, link, inherit := "ok", "ok", "ok", "ok"
	// The ACL step is a genuine no-op when the product's runtime uid IS the operator's: there
	// is one principal, and a default entry naming it twice grants nothing new.
	acl := "ok"
	if ruid == ouid {
		acl = "skipped"
	}
	var out strings.Builder
	switch k {
	case "ok":
	case "noown":
		own = "fail"
	case "noperm":
		perm = "fail"
	case "nolink":
		link = "fail"
	case "noacl":
		acl = "fail"
	case "noinherit":
		inherit = "fail"
	// A conforming image never does this: it reports the step SKIPPED where the two uids
	// differ and skipping is therefore not a no-op. The caller has to catch it.
	case "aclskip":
		acl = "skipped"
	// A stray refused= in a preflight transcript — preflight has no such key, so it must be
	// refused as outside this command's grammar, not passed over while every positive
	// observation is read.
	case "strayrefused":
		fmt.Fprintf(&out, "refused=%s/x:special-entry\n", dst)
	default:
		return 2, nil
	}
	fmt.Fprintf(&out, "ownership=%s\npermissions=%s\nsymlink=%s\nacl=%s\ninherit=%s\n",
		own, perm, link, acl, inherit)
	if own == "fail" || perm == "fail" || link == "fail" || inherit == "fail" || acl == "fail" {
		return h.fin(1, out.String())
	}
	return 0, []byte(out.String())
}

func (h *HelperImage) copy(args []string) (int, []byte) {
	if len(args) < 4 || args[0] == "" || args[1] == "" || args[2] == "" || args[3] == "" {
		return 1, nil
	}
	src, dst := args[0], args[1]
	mapf := ""
	if len(args) > 4 {
		mapf = args[4]
	}
	k := knob(h.Copy)
	if k == "silent" {
		return 0, nil
	}
	var out strings.Builder
	switch k {
	// `empty`: a copy that COMPLETED having enumerated ZERO source entries. `done=ok` over no
	// entries is a vacuous completion the caller must refuse — a copier that measured nothing
	// cannot be distinguished from one that lied. It skips the ordinary tree precisely so the
	// enumeration is empty.
	case "empty":
		return h.fin(0, "done=ok\n")
	// `stage-nonempty`: the copy container found its one writable mount NOT empty when it
	// reached it. `done=ok` is NOT printed.
	case "stage-nonempty":
		return h.fin(1, fmt.Sprintf("refused=%s/leftover:staging-nonempty\n", dst))
	// `count3`: a completed copy that enumerated exactly THREE source entries — a DIFFERENT
	// count from the ordinary five, so a test can prove the count that binds verification
	// TRACKS the copy's own enumeration and is not a constant.
	case "count3":
		fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/a\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/b\n", src)
		out.WriteString("done=ok\n")
		return h.fin(0, out.String())
	// `dup-entry`: a copier PADDING the entry count — one valid file enumerated twice, so a
	// `checked=` total could match a count that never included an omitted dangerous entry.
	case "dup-entry":
		fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/a\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/a\n", src)
		out.WriteString("done=ok\n")
		return h.fin(0, out.String())
	// `noncanon-pad`: the same file under two spellings — padding the count without adding a
	// distinct source object.
	case "noncanon-pad":
		fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/a\n", src)
		fmt.Fprintf(&out, "entry=file:%s/data/./a\n", src)
		out.WriteString("done=ok\n")
		return h.fin(0, out.String())
	// `empty-entry`: a claimed entry that names nothing.
	case "empty-entry":
		fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
		out.WriteString("entry=\n")
		out.WriteString("done=ok\n")
		return h.fin(0, out.String())
	// `emptytarget-lt`: a symlink whose disclosed linktarget PARSES but whose target suffix is
	// EMPTY — pathlen equals the whole body, so the symlink points at nothing.
	case "emptytarget-lt":
		fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
		fmt.Fprintf(&out, "entry=symlink:%s/data/link\n", src)
		out.WriteString(emitLinktarget(src+"/data/link", ""))
		out.WriteString("done=ok\n")
		return h.fin(0, out.String())
	}
	// The ordinary tree, reported on EVERY setting, so the contract observations are present
	// in the plain case too and a caller cannot pass its symlink assertions only on a knobbed
	// fixture. FIVE `entry=` lines: the copy's own source enumeration, and the count the
	// verify half is measured against. `linktarget=` is not an entry.
	fmt.Fprintf(&out, "entry=dir:%s/data\n", src)
	fmt.Fprintf(&out, "entry=file:%s/data/f\n", src)
	fmt.Fprintf(&out, "entry=file:%s/data/f3\n", src)
	fmt.Fprintf(&out, "entry=symlink:%s/data/link\n", src)
	out.WriteString(emitLinktarget(src+"/data/link", "../data/f"))
	fmt.Fprintf(&out, "entry=hardlink:%s/data/f2\n", src)
	rc := 0
	switch k {
	case "ok":
	case "special":
		fmt.Fprintf(&out, "entry=special:%s/dev/thing\n", src)
		fmt.Fprintf(&out, "refused=%s/dev/thing:special-entry\n", src)
		rc = 1
	// The copier ENUMERATED a device node and then did not refuse it — a one-line omission in
	// a real image, and one the caller must not accept on the strength of the exit status.
	case "special-unrefused":
		fmt.Fprintf(&out, "entry=special:%s/dev/thing\n", src)
	// A copier that reports a MISMATCH during the copy — as fatal as a refusal.
	case "copy-mismatch":
		fmt.Fprintf(&out, "mismatch=%s/data/f:digest\n", src)
	// An EMPTY mapped= on a copy that did NOT opt in — a reported mapping whose PRESENCE is
	// the problem; a value-iterating loop skips it.
	case "empty-mapped":
		out.WriteString("mapped=\n")
	// A line that is not a key=value record at all. An unparsed line means the transcript is
	// no longer a reliable record grammar, so it fails closed.
	case "junk-line":
		out.WriteString("not-a-key-value-record\n")
	// A well-formed key=value line whose KEY is not in this command's vocabulary.
	case "unknown-key":
		out.WriteString("surprise=whatever\n")
	// A BLANK LINE between records — a truncated continuation of a newline-bearing value looks
	// exactly like this, so the record grammar is no longer reliable.
	case "blank-line":
		fmt.Fprintf(&out, "entry=file:%s/a\n\ndone=ok\n", src)
		return h.fin(0, out.String())
	// An EMPTY linktarget= — a disclosed symlink target that names nothing.
	case "empty-lt":
		out.WriteString("linktarget=\n")
	// An EMPTY mapped= — a mapping record that names no uid; malformed whether or not opt-in
	// was set.
	case "empty-mapped-req":
		out.WriteString("mapped=\n")
	// An EMPTY stripped= — a privileged-bits observation of nothing.
	case "empty-stripped":
		out.WriteString("stripped=\n")
	// A linktarget disclosed for a path that was NOT enumerated as a symlink entry — a
	// contradiction (the relation is one-to-one), and a way to disclose a target for something
	// never enumerated.
	case "unassociated-lt":
		out.WriteString(emitLinktarget(src+"/data/ghost", "../data/f"))
	// TWO linktargets for one symlink — a contradiction that also lets a benign target be
	// shown beside an escaping one.
	case "dup-lt":
		out.WriteString(emitLinktarget(src+"/data/link", "../data/other"))
	// A type OUTSIDE the closed set: a copier that met a FIFO or a socket and enumerated it as
	// `fifo:`/`socket:` rather than `special:`, then exited 0 with done=ok. It counts toward
	// the total and the copy "verifies" unless EVERY entry's type is checked.
	case "unknown-type":
		fmt.Fprintf(&out, "entry=fifo:%s/data/q\n", src)
	case "unknown-socket":
		fmt.Fprintf(&out, "entry=socket:%s/data/s\n", src)
	// A malformed entry line with no path at all.
	case "entry-malformed":
		out.WriteString("entry=bogus-no-path\n")
	// A path containing a colon, so the caller's parse of `<path>:<reason>` is exercised on the
	// shape that breaks a first-colon split.
	case "colon":
		fmt.Fprintf(&out, "entry=special:%s/od:d/dev/thing\n", src)
		fmt.Fprintf(&out, "refused=%s/od:d/dev/thing:special-entry\n", src)
		rc = 1
	// A copier that ENUMERATED an escaping symlink (relative `..` climb) and then did NOT
	// refuse it. It exits 0 with done=ok; the caller must catch the escape from the linktarget
	// it logged, exactly as it does the enumerated-but-unrefused special entry.
	case "escape":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
		out.WriteString(emitLinktarget(src+"/data/evil", "../../../../etc/passwd"))
	// The same omission for an ABSOLUTE target, which escapes regardless of where the link sits.
	case "escape-abs":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
		out.WriteString(emitLinktarget(src+"/data/evil", "/etc/passwd"))
	// A symlink whose own PATH contains a colon, with an ABSOLUTE (escaping) target, logged but
	// NOT refused. A first-colon `<path>:<target>` split mis-splits the line here, reads the
	// target as a non-absolute string, and MISSES the escape while the copy succeeds.
	case "escape-colon-path":
		fmt.Fprintf(&out, "entry=symlink:%s/data/od:d/evil\n", src)
		out.WriteString(emitLinktarget(src+"/data/od:d/evil", "/etc/passwd"))
	// A symlink whose TARGET contains a colon and climbs above the root, logged but NOT
	// refused. The trailing length field keeps the colon inside the target from being read as
	// the path/target separator.
	case "escape-colon-target":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
		out.WriteString(emitLinktarget(src+"/data/evil", "../../../../a:b/etc"))
	// A linktarget whose trailing length field is NOT a number — an unparseable target. The
	// caller refuses it rather than guessing where the path ends: an unreadable target could
	// conceal one that escapes.
	case "linktarget-badlen":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
		fmt.Fprintf(&out, "linktarget=%s/data/evil../x:notanum\n", src)
	// A symlink entry with NO linktarget record and NO refused= line: the copier discloses the
	// entry but withholds its target, so the escape backstop has nothing to run on.
	case "symlink-no-linktarget":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
	// A CONFORMING copier that refuses the escaping symlink itself, in the reason-last grammar
	// the caller reads for its clear message.
	case "escape-refused":
		fmt.Fprintf(&out, "entry=symlink:%s/data/evil\n", src)
		out.WriteString(emitLinktarget(src+"/data/evil", "../../../../etc/passwd"))
		fmt.Fprintf(&out, "refused=%s/data/evil:escaping-symlink\n", src)
		rc = 1
	case "escaped-write":
		fmt.Fprintf(&out, "refused=%s/data/../outside:escaped-write\n", src)
		rc = 1
	case "setuid":
		fmt.Fprintf(&out, "entry=file:%s/bin/tool\n", src)
		fmt.Fprintf(&out, "stripped=%s/bin/tool:4755\n", src)
	case "foreign":
		if mapf == "--map-foreign" {
			fmt.Fprintf(&out, "mapped=%s/data/alien:4242\n", src)
		} else {
			fmt.Fprintf(&out, "refused=%s/data/alien:foreign-uid:4242\n", src)
			rc = 1
		}
	// A regressed or hostile copier that folds a foreign uid into the operator's and reports
	// the mapping on a DEFAULT invocation — one that never received --map-foreign.
	case "foreign-mapped-unrequested":
		fmt.Fprintf(&out, "mapped=%s/data/alien:4242\n", src)
	// A ZERO-PADDED <pathlen>. The reference reads that token in bash arithmetic, where a leading
	// zero means OCTAL — ":010" splits its body at 8, not 10 — so the escape check runs over the
	// wrong bytes. Here the true path is 21 bytes ("/src/data/od/evillink") and the length is
	// written "021": read as octal it is 17, read as decimal it is 21, and only one of those puts
	// the boundary where the copier said it is. The target escapes, so a reader that lands the
	// boundary wrong measures a different string and can miss it.
	case "escape-padded-len":
		out.WriteString("entry=symlink:/src/data/od/evillink\n")
		out.WriteString("linktarget=/src/data/od/evillink../../../../etc/passwd:021\n")
	// A symlink entry whose PATH IS NOT UNDER THE ROOT the escape rule is asked about, with an
	// innocuous relative target. The question "does this target climb out of /src?" cannot be
	// answered about a link that does not sit in /src, and a question that could not be asked is
	// never an answer of "no" — so it must be refused AS AN ESCAPE, not measured from a garbage
	// relative depth. (The reference's own fixture has no such knob.)
	case "symlink-outside-root":
		out.WriteString("entry=symlink:/elsewhere/evil\n")
		out.WriteString(emitLinktarget("/elsewhere/evil", "sibling"))
	// An EMPTY refused= record on the COPY step: a copier that refuses and names NOTHING, then
	// claims completion anyway. Its PRESENCE is the problem — the value-iterating refusal pass
	// drops it, so only a check by the KEY catches it. (The reference's own fixture has no such
	// copy-side knob, so its equivalent guard was never exercised; this one is.)
	case "empty-refused":
		out.WriteString("refused=\n")
	// COMPLETION IS STATED, NOT INFERRED: a copier that says `done=` something other than `ok`
	// has not said it finished, whatever its exit status. Returned here so the conforming
	// `done=ok` below cannot also be printed.
	case "done-not-ok":
		out.WriteString("done=notok\n")
		return h.fin(0, out.String())
	default:
		return 2, nil
	}
	// `done=ok` states COMPLETION, so it is printed only on a copy that completed. A refusal
	// that also claimed completion would be two contradictory answers in one response.
	if rc == 0 {
		out.WriteString("done=ok\n")
	}
	return h.fin(rc, out.String())
}

func (h *HelperImage) verify(args []string) (int, []byte) {
	// The restore-side read-only modes are distinguished by the SECOND argument, which can
	// never be the literal `/dst` an ordinary caller passes. They are not implemented here —
	// see the type's doc — so they answer with the contract's "not implemented" status rather
	// than a fabricated transcript.
	if len(args) > 1 {
		switch args[1] {
		case "--manifest", "--count", "--against-stdin":
			return 2, nil
		}
	}
	if len(args) < 4 || args[0] == "" || args[1] == "" || args[2] == "" || args[3] == "" {
		return 1, nil
	}
	dst, ruid, ouid := args[1], args[2], args[3]
	k := knob(h.Verify)
	if k == "silent" {
		return 0, nil
	}
	// The DEFAULT-ACL APPLICATION result on the COPIED tree: capability was proven at
	// preflight, this is proof it was actually applied. `skipped` is a genuine no-op ONLY when
	// the two principals are one uid.
	acl := "ok"
	if ruid == ouid {
		acl = "skipped"
	}
	// base5 is the "ordinary tree" count every Copy setting reports UNLESS it also adds an
	// entry= line of its own. Among the settings that reach a normal, completing verify, only
	// `setuid` does that — one extra entry beside the base five. A fixture-only
	// self-consistency rule: the caller binds `checked` to the COPY step's own enumeration,
	// which for Copy=setuid is genuinely 6.
	base5 := 5
	if h.Copy == "setuid" {
		base5 = 6
	}
	var out strings.Builder
	switch k {
	case "ok":
		fmt.Fprintf(&out, "checked=%d\nacl=%s\ndone=ok\n", base5, acl)
	// Completion claimed with no count: nothing in the answer says a single entry was looked at.
	case "nocount":
		fmt.Fprintf(&out, "acl=%s\ndone=ok\n", acl)
	// Completion claimed having checked ZERO entries — a vacuous pass the caller must reject
	// against a non-empty source.
	case "zero":
		fmt.Fprintf(&out, "checked=0\nacl=%s\ndone=ok\n", acl)
	// Fewer entries checked than the copy enumerated: an UNDERSTATED count.
	case "understate":
		fmt.Fprintf(&out, "checked=3\nacl=%s\ndone=ok\n", acl)
	// A stated `checked=` that is not a COUNT: it says something, so the absent-observation
	// rule does not fire, and only the digit check stands between it and a comparison against
	// a number nobody has.
	case "badcount":
		fmt.Fprintf(&out, "checked=many\nacl=%s\ndone=ok\n", acl)
	// A verifier that HONESTLY checked three entries — the conforming partner of the copy's
	// `count3`, so the end-to-end path passes when the copy also enumerated three, and no
	// constant count works for both.
	case "count3":
		fmt.Fprintf(&out, "checked=3\nacl=%s\ndone=ok\n", acl)
	case "type", "digest", "linktarget", "mode", "owner", "mtime", "hardlink":
		fmt.Fprintf(&out, "mismatch=%s/data/f:%s\n", dst, k)
		fmt.Fprintf(&out, "checked=5\nacl=%s\ndone=ok\n", acl)
		return h.fin(1, out.String())
	// The verifier REFUSED an entry (a device it could not compare, say) — a refusal is as
	// fatal in verification as in the copy, alongside an otherwise-conforming transcript.
	case "verify-refused":
		fmt.Fprintf(&out, "refused=%s/data/dev:special-entry\n", dst)
		fmt.Fprintf(&out, "checked=5\nacl=%s\ndone=ok\n", acl)
	// An EMPTY problem record — `refused=` / `mismatch=` with no value. Its PRESENCE is the
	// problem; a value-iterating check skips it.
	case "verify-empty-refused":
		out.WriteString("refused=\n")
		fmt.Fprintf(&out, "checked=5\nacl=%s\ndone=ok\n", acl)
	case "verify-empty-mismatch":
		out.WriteString("mismatch=\n")
		fmt.Fprintf(&out, "checked=5\nacl=%s\ndone=ok\n", acl)
	// A copied DIRECTORY missing the dual-principal default ACL — reported as a mismatch like
	// any other attribute (capability at preflight is not proof of application).
	case "default-acl":
		fmt.Fprintf(&out, "mismatch=%s/data:default-acl\n", dst)
		out.WriteString("checked=5\nacl=fail\ndone=ok\n")
		return h.fin(1, out.String())
	// acl=fail with NO accompanying mismatch: the positive-observation requirement standing on
	// its own, with the mismatch pass that normally backstops it silent.
	// It EXITS 0 deliberately: with a nonzero exit the run-completion check fires first (as it
	// does in the reference), and the acl arm would never be reached. A verifier that states
	// acl=fail and exits 0 anyway is exactly the regression the STATED-result rule is for.
	case "acl-fail-only":
		out.WriteString("checked=5\nacl=fail\ndone=ok\n")
	// The ACL application was never CHECKED: the answer omits the acl observation entirely.
	case "acl-absent":
		out.WriteString("checked=5\ndone=ok\n")
	// `skipped` reported where the two principals DIFFER: the ACL step is load-bearing there,
	// so a skip is a step that did not run.
	case "acl-skip-differ":
		out.WriteString("checked=5\nacl=skipped\ndone=ok\n")
	default:
		return 2, nil
	}
	return 0, []byte(out.String())
}

func (h *HelperImage) acl(args []string) (int, []byte) {
	if len(args) < 3 || args[0] == "" || args[1] == "" || args[2] == "" {
		return 1, nil
	}
	v := knob(h.ACL)
	out := "acl=" + v + "\n"
	if v != "ok" {
		return h.fin(1, out)
	}
	return 0, []byte(out)
}

func (h *HelperImage) access(args []string) (int, []byte) {
	if len(args) < 1 || args[0] == "" {
		return 1, nil
	}
	k := knob(h.Access)
	if k == "silent" {
		return 0, nil
	}
	switch k {
	case "ok":
		return 0, []byte("traverse=ok\nread=ok\nwrite=ok\n")
	// A PRESENT ACL entry limited by a restrictive mask: the entry is there, the access is not.
	// This is the case that makes "ACL presence is not effective access" more than a slogan.
	case "mask":
		return h.fin(1, "traverse=ok\nread=fail\nwrite=fail\n")
	case "notraverse":
		return h.fin(1, "traverse=fail\nread=fail\nwrite=fail\n")
	// A stray done= in an access transcript — access has no such key and does not act on one.
	case "straydone":
		return 0, []byte("traverse=ok\nread=ok\nwrite=ok\ndone=fail\n")
	}
	return 2, nil
}
