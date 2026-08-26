package verbs

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// THE GUARD FOR THE OWNER MAP IN owners.go.
//
// A partition written only as prose is a partition nobody re-checks. The failure it would hide is
// specific and quiet: a task whose share turns out awkward drops one entry, and the wave audit —
// which reads the map, not the bats files — reports full coverage over a set with a hole in it.
// So the map is checked against the bats files themselves, in BOTH directions, and against the
// counts stated in owners.go's own comment, so a silent edit has to falsify a written number too.
//
// WHEN THE BASH TREE IS DELETED (the cutover task), this test starts failing because the files it
// reads are gone. That is correct and intended: the map describes a porting obligation, so it dies
// with the thing it was porting. Delete owners.go and owners_test.go in that same commit rather
// than teaching either one to skip — a guard that learns to skip is a guard that is already off.

// The task numbers the map is allowed to use. Wave 5 is Tasks 22-24 and nothing else; a typo'd 25
// would otherwise create a share no task ever claims.
var wave5Tasks = map[int]bool{22: true, 23: true, 24: true}

// The three bats files and the number of tests each holds. The counts are exact, not floors: the
// bash tree is FROZEN for the whole port, so a changed count means either the freeze was broken or
// the parser below stopped seeing tests it used to see. Both are worth a red.
var batsFiles = map[string]int{
	"tests/unit/verbs.bats":           81,
	"tests/acceptance/lifecycle.bats": 16,
	"tests/unit/repair.bats":          47,
}

// The shares stated in owners.go's comment, repeated here so the two must be changed together.
var wave5Shares = map[int]int{22: 50, 23: 47, 24: 47}

// repoRoot walks up from the test's working directory (the package directory) to the module root.
// Failing to find it is a hard error: a helper that silently returned "" would make every file
// read below miss, and a miss reads exactly like a file with no tests in it.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod found walking up from the test's working directory")
		}
		dir = parent
	}
}

var batsTestLine = regexp.MustCompile(`^@test "(.*)" \{$`)

// batsTestNames returns the test names defined in one bats file, in file order.
func batsTestNames(t *testing.T, root, rel string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("open %s: %v", rel, err)
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if m := batsTestLine.FindStringSubmatch(sc.Text()); m != nil {
			names = append(names, m[1])
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return names
}

func TestOwnerMapPartitionsBats(t *testing.T) {
	root := repoRoot(t)

	// Direction 1: every bats test has exactly one owner.
	// The count assertion runs FIRST. Without it, a parser that matched nothing would make the
	// "every test is owned" loop vacuously true and this whole test a no-op that reports green.
	found := map[batsTest]bool{}
	for rel, want := range batsFiles {
		names := batsTestNames(t, root, rel)
		if len(names) != want {
			t.Fatalf("%s: parsed %d tests, expected %d — the frozen bash tree changed, or the parser stopped matching",
				rel, len(names), want)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] {
				t.Errorf("%s: two tests share the name %q — the map cannot address them separately", rel, n)
			}
			seen[n] = true
			k := batsTest{File: rel, Name: n}
			found[k] = true
			if _, ok := batsOwner[k]; !ok {
				t.Errorf("%s: no owner for %q", rel, n)
			}
		}
	}

	// Direction 2: every owner entry names a bats test that exists. A phantom entry is how a share
	// inflates to look complete: it counts toward a task's total while covering nothing.
	for k, task := range batsOwner {
		if !found[k] {
			t.Errorf("owner map names a test that does not exist: %s: %q", k.File, k.Name)
		}
		if !wave5Tasks[task] {
			t.Errorf("%s: %q is assigned to task %d, which is not in Wave 5", k.File, k.Name, task)
		}
	}

	// The shares, against the numbers owners.go states in prose.
	got := map[int]int{}
	for _, task := range batsOwner {
		got[task]++
	}
	for task, want := range wave5Shares {
		if got[task] != want {
			t.Errorf("task %d owns %d tests, but owners.go states %d", task, got[task], want)
		}
	}
	for task := range got {
		if _, ok := wave5Shares[task]; !ok {
			t.Errorf("task %d has a share (%d tests) that owners.go does not state", task, got[task])
		}
	}

	// The deliberate empty share: Task 24 owns nothing in the two SHARED files. This is the one
	// place the map says something by omission, so it is asserted rather than left to be read as an
	// oversight by whoever audits the wave.
	for k, task := range batsOwner {
		if task == 24 && k.File != "tests/unit/repair.bats" {
			t.Errorf("task 24 owns %q in %s; its share of the shared files is deliberately empty", k.Name, k.File)
		}
	}
}
