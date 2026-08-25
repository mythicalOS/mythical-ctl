// Package famlock is the family-scoped operation lock (D31/§4b.3a): it serializes every
// mutating operation so read-modify-write on the ledger and mythical.conf cannot interleave.
//
// MECHANISM CHANGE, DELIBERATE AND DOCUMENTED (the rewrite plan's Task 7): the bash used an
// atomic-`ln` lock file with pid-liveness reads and a serialized recovery gate, because
// portable shell has no flock. Go has flock(2), and the kernel then owns the whole problem: a
// dead holder's lock vanishes with its file description (no stale-break protocol at all), two
// live holders are impossible, and the crash-inside-recovery manual-clear case ceases to
// exist. The lock file PATH (.state/lock) and 0600 mode are unchanged; the `pid=` body is now
// diagnostic only. Nothing on disk is shared with a bash instance — the bash was never
// released — so no mixed-implementation locking can occur. RECOVERY.md's stale-lock section
// retires at cutover.
//
// AUTHORIZATION MODEL. Held is a SEALED interface: its method is unexported so no outside
// package can implement it, and the implementing struct is unexported so `new()` cannot mint
// one — the only forgeable value is nil (or an embedding wrapper), and Assert catches both by
// exact-type-asserting the concrete token. Every mutating API in the tree takes a Held AND
// calls Assert first: the type narrows at compile time, the assert fails closed at runtime.
// The token is BOUND TO THE HOME it authorizes — guarded packages derive the home from the
// token via HomeOf, never from a separate parameter, so a lock acquired for home A cannot
// authorize a mutation of home B.
package famlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Held is the sealed capability. Only Acquire mints one.
type Held interface {
	sealedFamlockToken() *held
}

type held struct {
	home     string
	f        *os.File
	released bool
}

func (h *held) sealedFamlockToken() *held { return h }

// ErrBusy wraps the holder's pid (best-effort, diagnostic only) when the lock is held
// elsewhere.
var ErrBusy = errors.New("another mythical-ctl operation is in progress")

// Acquire takes the family lock for home. It creates .state/ if missing — on a fresh machine
// no verb has made the layout yet, and mis-reporting a missing directory as lock contention
// ("try again shortly", forever) was a real bash bug this preserves the fix for. The lock file
// opens with O_NOFOLLOW and is fstat-verified a regular file with link count 1 BEFORE
// flocking: the bash's `ln` mechanism never opened an existing target, so a symlink or
// hardlink planted at the path could not redirect it — the flock port must refuse the
// substituted target instead.
func Acquire(home string) (Held, error) {
	ld := filepath.Join(home, ".state")
	if err := os.MkdirAll(ld, 0o755); err != nil {
		return nil, fmt.Errorf("lock: cannot create the lock directory %q: %w", ld, err)
	}
	path := filepath.Join(ld, "lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lock: cannot open %q: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("lock: cannot stat %q: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("lock: %q is not a regular file — refusing a substituted lock target", path)
	}
	// *syscall.Stat_t, not *unix.Stat_t: os.FileInfo.Sys() hands the syscall type, and a
	// failed type assertion here silently SKIPPED the check in the first draft — fail-open in
	// the one place that refuses substituted targets. Unknown stat shape now refuses too.
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		f.Close()
		return nil, fmt.Errorf("lock: cannot verify %q's link count — refusing", path)
	}
	if sys.Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("lock: %q has %d links — refusing a hardlinked lock target", path, sys.Nlink)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := readHolderPID(f)
		f.Close()
		if holder != "" {
			return nil, fmt.Errorf("%w (pid %s) — try again when it finishes", ErrBusy, holder)
		}
		return nil, fmt.Errorf("%w — try again when it finishes", ErrBusy)
	}
	// Ours. Stamp the diagnostic body (never authorization — the flock is that).
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("pid=%d\n", os.Getpid())), 0)
	return &held{home: home, f: f}, nil
}

func readHolderPID(f *os.File) string {
	buf := make([]byte, 64)
	n, _ := f.ReadAt(buf, 0)
	s := strings.TrimSpace(string(buf[:n]))
	if rest, ok := strings.CutPrefix(s, "pid="); ok {
		if _, err := strconv.Atoi(rest); err == nil {
			return rest
		}
	}
	return ""
}

// Release marks the token dead BEFORE dropping the flock, so a use-after-release fails
// Assert. Releasing an already-released token is a safe no-op, and a nil token releases
// nothing — matching the bash's "release is a safe no-op when not held".
func Release(h Held) error {
	t := concrete(h)
	if t == nil || t.released {
		return nil
	}
	t.released = true
	err := t.f.Close() // closing the fd drops the flock
	return err
}

// Assert is the runtime backstop behind the sealed type: it fails closed on nil, on a
// released token, and on anything that is not THIS package's concrete token (an embedding
// wrapper delegates the sealed method but cannot forge the concrete type). <what> completes
// the sentence "refusing to <what> without holding the family lock".
func Assert(h Held, what string) error {
	if concrete(h) == nil {
		return fmt.Errorf("refusing to %s without holding the family lock (D28/§4b.3a)", what)
	}
	return nil
}

// HomeOf is the ONLY way guarded packages read the home a token authorizes — exact-type
// checked like Assert, so a wrapper cannot launder home-A authority into home B.
func HomeOf(h Held) (string, error) {
	t := concrete(h)
	if t == nil {
		return "", errors.New("famlock: no valid token")
	}
	return t.home, nil
}

// concrete unwraps to this package's own token, or nil: a nil interface, a released token,
// and a foreign/embedding implementation all fail. The double check (the sealed method
// returns the receiver; we then require identity) is what defeats an embedded-delegation
// wrapper that overrides other methods — the returned *held is ours by construction.
func concrete(h Held) (t *held) {
	if h == nil {
		return nil
	}
	// An embedding wrapper around a NIL inner token panics when the promoted method hits the
	// nil interface — and a broken or hostile wrapper must fail CLOSED, never crash the
	// process that was refusing it. The recover turns any such panic into "no token".
	defer func() {
		if recover() != nil {
			t = nil
		}
	}()
	t = h.sealedFamlockToken()
	if t == nil || t.released {
		return nil
	}
	return t
}
