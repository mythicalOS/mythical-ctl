package prov

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"mythicalos.ai/ctl/internal/layout"
	"mythicalos.ai/ctl/internal/manifest"
)

// FirstUse answers §6b.3: is this genuinely a first install?
//
// "No ledger" is only first use when NOTHING ELSE is there either. An earlier revision of the
// reference said absence means a fresh installation AND claimed a backup restored without the
// ledger would be detected — which cannot both hold if absence is unconditionally benign. The
// distinguishing evidence is not the ledger; it is everything else the installer would have
// created.
//
// nil genuinely first use · ErrNotFirstUse a ledger exists (an answer, not a refusal) · any other
// error INCONSISTENT, and it carries the reason.
func FirstUse(ctx context.Context, home string, objs Objects) error {
	led := filepath.Join(home, ".state", "ledger")

	// PRESENCE IS THE EVIDENCE, NOT READABILITY — and "is it a regular file" asks the wrong
	// question on its own. A failed or partial restore leaves the ledger path as a DIRECTORY or as
	// a dangling symlink; a regular-file test is false for both, so with no other trace beside it
	// the machine was declared fresh — and a fresh machine is one this installer initialises over.
	// Lstat is what sees the link ITSELF rather than what it points at, which is why a dangling
	// symlink is visible here at all.
	if li, err := os.Lstat(led); err == nil {
		if li.Mode().IsRegular() {
			return ErrNotFirstUse
		}
		return errors.New("prov: the installer state ledger is present but is not a regular file — a directory, a\n" +
			"  dangling symlink or a device node, which is what a failed restore leaves behind.\n" +
			"  Something is there, so this is not a first install; it is inconsistent, and it is\n" +
			"  reported rather than initialised over.\n" +
			"  Run 'mythical-ctl state repair'.")
	} else if !errors.Is(err, fs.ErrNotExist) {
		// Present-but-unstattable says nothing about absence: refuse rather than read a failed
		// question as "there is nothing here".
		return fmt.Errorf("prov: the installer state ledger path could not be examined, so absence cannot be\n"+
			"  established — refusing rather than treating this as a fresh machine: %w", err)
	}

	// ONE SWEEP, ONE PRESENCE QUESTION, ASKED OF EVERY ENTRY.
	//
	// The reference's two loops over two globs let THE GLOB — not the test beside it — decide
	// which entries got judged: bash expands a trailing-slash pattern by testing each candidate
	// for directory-ness, so a dangling `<product> -> /gone` never became a candidate and the test
	// next to it never ran. A directory READ offers every entry — file, directory, live link and
	// dangling link alike — and the tests below decide. (The reference's GLOBIGNORE defenses have
	// nothing to defend here: there is no glob, and a directory read cannot be filtered by an
	// ambient variable.)
	var found []string
	entries, rerr := os.ReadDir(home)
	if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
		return fmt.Errorf("prov: the family home could not be read, so 'nothing else is there' cannot be\n"+
			"  established — refusing rather than treating this as a fresh machine: %w", rerr)
	}
	for _, e := range entries {
		b := e.Name()
		switch b {
		// DELIBERATE EXEMPTIONS, each for its own reason — not "these are not traces":
		//   mythical.conf      the family file is not evidence of any PRODUCT being installed.
		//   bin, .state        this installer's own scaffolding, created on every run including
		//                      the one asking the question, so counting them would make no
		//                      machine ever read as first use.
		//   transcripts, logs  user data (§6c): they are the home's original meaning and can
		//                      predate the installer entirely, so they are not evidence of a
		//                      previous INSTALLATION. They are still swept as data everywhere else.
		// Each is exempt whatever it is on disk — a dangling symlink named `bin` is exempt too, on
		// purpose, because the exemption is about what the NAME means, not what is at the path.
		case "mythical.conf", "bin", ".state", "transcripts", "logs":
			continue
		}
		p := filepath.Join(home, b)
		// A per-product config, readable or not: a dangling symlink named <product>.conf is as
		// much a trace of a previous installation as a readable file is.
		if strings.HasSuffix(b, ".conf") {
			found = append(found, b)
			continue
		}
		li, lerr := os.Lstat(p)
		if lerr != nil {
			// It was listed a moment ago, so it is present; a failed look is not an absence.
			found = append(found, b)
			continue
		}
		isLink := li.Mode()&fs.ModeSymlink != 0
		// ONE EXEMPTION (the host-tool slot): a REAL product directory holding nothing but
		// `<product>/cli.toml` is not evidence of a previous INSTALLATION. That file belongs to
		// the product's host-side tool, which an operator can install and configure before this
		// installer has ever run here — so counting it would refuse the very first install as
		// "inconsistent" and send them to 'state repair' over a file they meant to create. A
		// SYMLINK standing where the directory should be is NOT exempt, whatever it resolves to:
		// the exemption is about a directory this layout owns, and the zone classifier classifies
		// home-relative paths, not link targets somewhere else on the disk.
		if !isLink && hostToolOnly(home, b) {
			continue
		}
		if st, serr := os.Stat(p); serr == nil && st.IsDir() {
			found = append(found, b+"/")
			continue
		}
		if isLink {
			found = append(found, b)
			continue
		}
		// Anything else here is a plain file at a name this installer never creates — not evidence.
	}

	// A STAGING ledger is its own third state (§6c/D59): an in-progress restore is not first use
	// and not inconsistent.
	//
	// BUT ONLY A REGULAR FILE IS THAT STATE, AND THE OTHER THREE ANSWERS ARE NOT IT. This asked
	// one question — `Lstat succeeded` — and folded four facts into two wrong ones.
	//
	//   - A DIRECTORY, a device node or a symlink at that path got the RESUMABLE-RESTORE
	//     diagnostic and its two prescribed commands. Neither command can act on it: the restore
	//     verb classifies the machine first and REFUSES a staging path that is not a regular
	//     file, so the operator was handed instructions whose only possible outcome is a second
	//     refusal. That is an ANSWER ("a restore is in progress, here is how to finish it") given
	//     where the truth is a REFUSAL ("something is there that nothing can classify").
	//   - An Lstat that FAILED for any other reason fell straight through toward GENUINE FIRST
	//     USE — the fail-open on the single thing this function decides. "I could not look" is
	//     not "there is nothing here", and this is the one path where reading it that way ends in
	//     initialising over a machine that is not fresh.
	//
	// So the four are separated: regular ⇒ resume, present-but-not-regular ⇒ inconsistent,
	// ENOENT ⇒ genuinely absent (fall through), anything else ⇒ refuse.
	// THE PRESCRIBED COMMANDS ARE THE ONES THE CLI ACTUALLY HAS. This diagnostic named a
	// `restore --resume` flag that does not exist and never did: the option loop refuses any
	// unknown `-*` before the verb runs, so an operator following it literally got
	// "unknown option: --resume", exit 2 — at precisely the moment they are recovering from an
	// interrupted restore. Resuming is RE-RUNNING the verb: `restore` classifies the machine
	// first and, on a staging ledger that still carries a live intent, resumes from the source
	// directory recorded INSIDE that intent rather than from the operand. The operand is still
	// required (the verb takes exactly one, or --abandon alone), which is why the instruction
	// names the same directory rather than pretending none is needed. Both strings are pinned by
	// TestFirstUseStaging and re-driven through the real dispatcher by the cmd package's
	// TestStagingDiagnosticPrescribesRunnableCommands, so renaming either breaks a test instead
	// of an operator.
	//
	// NO APOSTROPHE IN THE PROSE OF THIS MESSAGE. Single quotes delimit the commands, so a
	// possessive in the surrounding sentence closes one prescription early and swallows the next
	// — which is not a cosmetic problem: the reader that extracts these commands and runs them
	// then never sees the second one. Measured while writing this fix; the guard is
	// TestStagingDiagnosticPrescribesRunnableCommands, which requires that this diagnostic
	// prescribes BOTH commands and that each one, run on a fresh machine in this exact state, is
	// neither a usage error nor answered by the verb with "there is nothing here I can act on".
	staging := filepath.Join(home, ".state", "ledger.staging")
	switch si, serr := os.Lstat(staging); {
	case serr == nil && si.Mode().IsRegular():
		return errors.New("prov: there is no active ledger, but a restore is in progress (.state/ledger.staging).\n" +
			"  Resume it by re-running 'mythical-ctl restore <the same backup directory>' — the source\n" +
			"  directory is recorded inside the staging ledger, so re-running continues that attempt\n" +
			"  rather than starting a new one.\n" +
			"  Or give it up with 'mythical-ctl restore --abandon', which removes the partial volumes\n" +
			"  that attempt created under their recorded identity.")
	case serr == nil:
		// PRESENT, SO NOT FIRST USE — and unclassifiable, so not a resumable restore either.
		// Prescribing resume or abandon here would send the operator to a verb that refuses this
		// exact path, which is a recovery instruction whose only outcome is a second refusal.
		return errors.New("prov: the restore staging ledger is present but is not a regular file — a directory, a\n" +
			"  symlink or a device node (.state/ledger.staging).\n" +
			"  Something is there, so this is not a first install; but it is also not a restore that can\n" +
			"  be resumed or abandoned: the restore verb refuses a staging path it cannot classify, so\n" +
			"  neither of those commands can act on this. It is reported instead.\n" +
			"  Run 'mythical-ctl state repair'.")
	case !errors.Is(serr, fs.ErrNotExist):
		return fmt.Errorf("prov: the restore staging ledger path could not be examined, so absence cannot be\n"+
			"  established — refusing rather than treating this as a fresh machine: %w", serr)
	}

	if len(found) > 0 {
		return fmt.Errorf("prov: there is no installer state ledger, but this home already holds: %s\n"+
			"  A fresh machine does not have product configs or generated directories, so this is\n"+
			"  inconsistent — most often a backup restored without the installer state ledger.\n"+
			"  Run 'mythical-ctl state repair' to rebuild what is reconstructible.", strings.Join(found, " "))
	}

	// And labelled runtime objects, which survive removing the family home entirely (§3a).
	//
	// There is no identity to filter by (the ledger that held it is absent), so ask a question
	// that does not need one: does ANY object carry a name this installer's scheme would produce?
	// The prefix is ours by construction, so a match is either our own object from a previous
	// install or a collision — both of which make "fresh machine" false. A find-by-label sweep
	// cannot stand in for this: every label filter needs the installation identity as its value,
	// and the identity is precisely what is missing.
	//
	// AND AN EMPTY ANSWER IS NOT THE SAME FACT AS NO ANSWER. The reference's listings swallowed
	// every failure, so a daemon that was down or refusing to answer produced three empty listings
	// and the function returned "genuinely first use" off the strength of a question it never got
	// to ask. That is a fail-open on the single thing this function decides.
	if objs == nil {
		return errors.New("prov: no runtime to ask — 'no ledger' is only a first install once the runtime has\n" +
			"  ANSWERED that it holds none of ours.")
	}
	var anyobj, unasked []string
	for _, class := range []Class{ClassContainer, ClassVolume, ClassNetwork} {
		names, err := objs.Names(ctx, class)
		if err != nil {
			unasked = append(unasked, string(class))
			continue
		}
		for _, n := range names {
			if strings.HasPrefix(n, manifest.NamePrefix+"-") {
				anyobj = append(anyobj, string(class)+":"+n)
			}
		}
	}
	if len(unasked) > 0 {
		return fmt.Errorf("prov: there is no installer state ledger, and the container runtime could not be asked\n"+
			"  what it holds (%s).\n"+
			"  Labelled objects survive removing the home directory entirely, so 'no ledger' is only\n"+
			"  a first install once the runtime has ANSWERED that it holds none of ours.\n"+
			"  Start the container runtime and run this again.", strings.Join(unasked, " "))
	}
	if len(anyobj) > 0 {
		return fmt.Errorf("prov: there is no installer state ledger, but the container runtime already holds\n"+
			"  labelled or family-named objects: %s\n"+
			"  This is inconsistent — refusing to treat the machine as a first install.\n"+
			"  Run 'mythical-ctl state repair'.", strings.Join(anyobj, " "))
	}
	return nil
}

// hostToolOnly reports whether <rel> — ONE home-relative component — is a real directory holding
// at least one host-tool slot and NOTHING that is not one. Every entry in it is put to the zone
// classifier, so this exemption and the ownership contract cannot drift apart: the day another
// leaf becomes user-owned, this follows without being edited.
//
// FAIL CLOSED, IN BOTH DIRECTIONS THAT MATTER. An unreadable directory is not exempt, because "I
// could not look" must never become "there is nothing here". An EMPTY directory is not exempt
// either, and that is a different rule, not the same one: an empty product directory has always
// been a trace, and turning it into a non-trace here would widen the exemption past the file it
// exists for. Hence `seen`: the slot must be PRESENT, not merely unopposed.
//
// The slot must be a plain regular file. A directory or a symlink at that name is not the
// host-tool config the contract describes, and exempting a DIRECTORY called `cli.toml` would hide
// a whole generated subtree behind a reserved name.
//
// THE NAME IS VALIDATED IN THE ZONE CLASSIFIER, ONCE — its one authority. `Brokkr/`, `mythical/`
// and `fooBAR/` are not user-owned there, so a slot under any of them is not exempt here, and this
// function needs no product-name check of its own. A guard no input reaches is not defence in
// depth; it is a guard whose removal no test would notice.
func hostToolOnly(home, rel string) bool {
	d := filepath.Join(home, rel)
	entries, err := os.ReadDir(d)
	if err != nil {
		return false
	}
	seen := false
	for _, e := range entries {
		// Hidden entries are included: a directory read has no dotfile blind spot, and a hidden
		// generated artifact must not be invisible to a question whose entire job is to notice one.
		if layout.ZoneOf(rel+"/"+e.Name()) != layout.ZoneUserOwned {
			return false
		}
		li, lerr := os.Lstat(filepath.Join(d, e.Name()))
		if lerr != nil || li.Mode()&fs.ModeSymlink != 0 || !li.Mode().IsRegular() {
			return false
		}
		seen = true
	}
	return seen
}
