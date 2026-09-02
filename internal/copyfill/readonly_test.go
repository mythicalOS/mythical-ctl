package copyfill_test

import (
	"context"
	"strings"
	"testing"

	"mythicalos.ai/ctl/internal/engine/enginetest"
)

// Inventory — the three READ-ONLY modes of `verify` (the backup/restore direction). They have no
// row in tests/unit/copy.bats: the reference implements them in lib/backup.sh, whose own rows are
// claimed by internal/backup, and what is asserted HERE is the half that lives in this module —
// the LAUNCH each mode makes, which no bats row in either file observes directly.
//
// Inventory — NONE, and that is the point of the paragraph above. No bats row states this; a
// claim-syntax line naming one ("the manifest is produced by the pinned copy container, on stdin
// for verify") would be a summary of the reference's prose, reading as coverage of a test that
// does not exist in the corpus.
// The behaviour is real and asserted below; it simply has no bats row to be the port OF.

// stdinSpy records what the helper was handed on its stdin, which is the only evidence that the
// manifest crossed into the container rather than being dropped by the seam.
type stdinSpy struct {
	img  *enginetest.HelperImage
	cmds [][]string
	in   [][]byte
}

func (s *stdinSpy) entry(cmd string, args []string, view enginetest.HelperNetView, stdin []byte) (int, []byte) {
	s.cmds = append(s.cmds, append([]string{cmd}, args...))
	s.in = append(s.in, append([]byte(nil), stdin...))
	return s.img.Entry(cmd, args, view, stdin)
}

func spyRig(t *testing.T) (*rig, *stdinSpy) {
	t.Helper()
	r := newRig(t)
	sp := &stdinSpy{img: r.img}
	r.fake.HelperEntry = sp.entry
	return r, sp
}

// TestReadOnlyVerifyModesLaunchContract pins what all three modes must and must not do.
//
// ONE VOLUME, READ-ONLY, AND NOTHING ELSE. These modes enumerate or compare; they never map
// ownership and they never write. A writable mount, a second host path, a network, or a `--user`
// would each be a capability the question does not need — and the manifest mode in particular runs
// against a volume holding every byte of a product's data.
func TestReadOnlyVerifyModesLaunchContract(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(r *rig) (string, int, error)
		arg  string
	}{
		{"manifest", func(r *rig) (string, int, error) {
			return r.c.Enumerate(context.Background(), r.ix, "srcvol1")
		}, "--manifest"},
		{"count", func(r *rig) (string, int, error) {
			return r.c.Count(context.Background(), r.ix, "srcvol1")
		}, "--count"},
		{"against-stdin", func(r *rig) (string, int, error) {
			return r.c.VerifyAgainstManifest(context.Background(), r.ix, "srcvol1", []byte("manifest=file:/src/x\n"))
		}, "--against-stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			if _, _, err := tc.call(r); err != nil {
				t.Fatalf("the helper could not be run: %v", err)
			}
			ls := r.fake.HelperLaunches()
			if len(ls) != 1 {
				t.Fatalf("expected exactly one helper launch, got %d", len(ls))
			}
			l := ls[0]
			want := enginetest.HelperMount{Type: "volume", Source: "srcvol1", Target: "/src", ReadOnly: true}
			// AN EXACT SET, not a containment: a container carrying a writable second mount
			// satisfies "the one we wanted is present" just as well.
			if len(l.Mounts) != 1 || l.Mounts[0] != want {
				t.Fatalf("mounts: %+v, want exactly %+v", l.Mounts, want)
			}
			if l.NetMode != "none" || l.Network != "" || len(l.Aliases) != 0 {
				t.Fatalf("these modes run private: %+v", l)
			}
			if l.User != "" {
				t.Fatalf("a read of a volume must not run as a mapped principal: --user %q", l.User)
			}
			if l.Image != copyRef {
				t.Fatalf("the read runs the PINNED image: %q", l.Image)
			}
			if got := strings.Join(l.Cmd, " "); got != "verify /src "+tc.arg {
				t.Fatalf("argv: %q, want %q", got, "verify /src "+tc.arg)
			}
		})
	}
}

// TestVerifyAgainstManifestCarriesTheManifestOnStdin is the one that would catch the seam this
// task had to open in the first place: before it, the helper door never set Stdin at all, so the
// manifest could not reach the container by any route that did not mount a third host path.
//
// THE FIXTURE ANSWERS FROM WHAT IT READ. `checked=` is the number of `manifest=` records the
// helper saw on stdin, so a dropped payload does not merely fail an assertion about bytes — it
// changes the ANSWER, which is exactly how the restore's count binding catches it.
func TestVerifyAgainstManifestCarriesTheManifestOnStdin(t *testing.T) {
	r, sp := spyRig(t)
	man := "manifest=dir:/src/data\nmanifest=file:/src/data/f\nmanifest=file:/src/data/g\n"
	text, code, err := r.c.VerifyAgainstManifest(context.Background(), r.ix, "srcvol1", []byte(man))
	if err != nil || code != 0 {
		t.Fatalf("verify --against-stdin: code=%d err=%v", code, err)
	}
	if len(sp.in) != 1 || string(sp.in[0]) != man {
		t.Fatalf("the helper was handed %q on stdin, want %q", sp.in, man)
	}
	if !strings.Contains(text, "checked=3\n") {
		t.Fatalf("the helper did not answer from what it read: %q", text)
	}
}

// TestOtherModesOpenNoStdin: the two enumerating modes hand the helper nothing, and a mode that
// opened an input stream it never writes would leave a container waiting on a stream nobody
// closes — under the family lock.
func TestOtherModesOpenNoStdin(t *testing.T) {
	r, sp := spyRig(t)
	if _, _, err := r.c.Enumerate(context.Background(), r.ix, "srcvol1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.c.Count(context.Background(), r.ix, "srcvol1"); err != nil {
		t.Fatal(err)
	}
	for i, in := range sp.in {
		if len(in) != 0 {
			t.Fatalf("call %d was handed %q on stdin", i, in)
		}
	}
}

// TestReadOnlyModesReturnTheTranscriptUNREAD is the seam's own shape, asserted rather than
// assumed: these three doors hand back exactly what the helper said and the status beside it, and
// form no verdict of their own. The reading is internal/backup's, whose refusals are specified
// against the transcript; a judgement made here would be a second copy of those rules.
//
// A HELPER THAT STATED NOTHING AND EXITED 0 IS THE CASE THAT MATTERS. It must arrive as an empty
// transcript with a zero status — not as an error, and not as an invented default — because
// "unmeasured is not measured-clean" is a refusal its CALLER owes, and a door that decided here
// would take that decision away from the module that owns it.
func TestReadOnlyModesReturnTheTranscriptUnread(t *testing.T) {
	r := newRig(t)
	r.img.Manifest = "silent"
	r.img.Count = "silent"
	r.img.RestoreVerify = "silent"
	for _, tc := range []struct {
		name string
		call func() (string, int, error)
	}{
		{"manifest", func() (string, int, error) { return r.c.Enumerate(context.Background(), r.ix, "srcvol1") }},
		{"count", func() (string, int, error) { return r.c.Count(context.Background(), r.ix, "srcvol1") }},
		{"against-stdin", func() (string, int, error) {
			return r.c.VerifyAgainstManifest(context.Background(), r.ix, "srcvol1", []byte("manifest=x\n"))
		}},
	} {
		text, code, err := tc.call()
		if err != nil {
			t.Fatalf("%s: a helper that ran must not be reported as one that could not: %v", tc.name, err)
		}
		if text != "" || code != 0 {
			t.Fatalf("%s: got (%q, %d), want the silent answer verbatim", tc.name, text, code)
		}
	}
}

// TestReadOnlyModesReportAHelperThatFailed keeps the other half apart: a helper that RAN and
// failed reports itself in the exit status, and the status must survive the door untouched. An
// error is reserved for a helper that could not be run at all.
func TestReadOnlyModesReportAHelperThatFailed(t *testing.T) {
	r := newRig(t)
	r.img.RestoreVerify = "type-symlink-as-file"
	text, code, err := r.c.VerifyAgainstManifest(context.Background(), r.ix, "srcvol1", []byte("manifest=file:/src/data/link\n"))
	if err != nil {
		t.Fatalf("a check that ran and failed is not a helper that could not run: %v", err)
	}
	if code != 1 {
		t.Fatalf("code = %d, want 1 — the failing status must reach the caller", code)
	}
	if !strings.Contains(text, "mismatch=") {
		t.Fatalf("the transcript lost the finding: %q", text)
	}
}

// TestReadOnlyModesRefuseAnUnverifiedIndex: the copy image is read from the VERIFIED family index
// and nowhere else. A nil index cannot name one, and these doors must refuse rather than launch
// something unpinned — they hand a container every byte of a product's data.
func TestReadOnlyModesRefuseAnUnverifiedIndex(t *testing.T) {
	r := newRig(t)
	if _, _, err := r.c.Enumerate(context.Background(), nil, "srcvol1"); err == nil {
		t.Fatal("Enumerate accepted a nil index")
	}
	if _, _, err := r.c.Count(context.Background(), nil, "srcvol1"); err == nil {
		t.Fatal("Count accepted a nil index")
	}
	if _, _, err := r.c.VerifyAgainstManifest(context.Background(), nil, "srcvol1", nil); err == nil {
		t.Fatal("VerifyAgainstManifest accepted a nil index")
	}
	if n := len(r.fake.HelperLaunches()); n != 0 {
		t.Fatalf("%d helper(s) were launched from an unverified index", n)
	}
}

// TestReadOnlyModesRefuseAnUnusableVolumeName: the volume name reaches the daemon as a mount
// source, and the closed mount vocabulary is what validates it. A refused name must stop before
// any container is created.
func TestReadOnlyModesRefuseAnUnusableVolumeName(t *testing.T) {
	r := newRig(t)
	for _, bad := range []string{"", "has space", "comma,name"} {
		if _, _, err := r.c.Enumerate(context.Background(), r.ix, bad); err == nil {
			t.Fatalf("Enumerate accepted volume name %q", bad)
		}
	}
	if n := len(r.fake.HelperLaunches()); n != 0 {
		t.Fatalf("%d helper(s) were launched for an unusable volume name", n)
	}
}
