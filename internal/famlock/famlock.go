// Package famlock is the family-scoped operation lock (D31/§4b.3a): it serializes every
// mutating operation so read-modify-write on the ledger and mythical.conf cannot interleave.
//
// MECHANISM CHANGE FROM THE REFERENCE, DELIBERATE AND DOCUMENTED: the bash used an
// atomic-`ln` lock file with pid-liveness reads and a serialized recovery gate, because
// portable shell has no flock. Go has flock(2), and the kernel then owns the whole problem: a
// dead holder's lock vanishes with its file description (no stale-break protocol at all), two
// live holders are impossible, and the crash-inside-recovery manual-clear case ceases to
// exist. The lock file PATH (.state/lock) and 0600 mode are unchanged; the `pid=` body is now
// diagnostic only. Nothing on disk is shared with a bash instance — the bash was never
// released — so no mixed-implementation locking can occur. RECOVERY.md turned out to have no
// stale-lock section to retire — the procedure lived in the shell, not in the published doc — so
// the cutover ADDED one ("Another operation is in progress") saying the opposite: there is no
// stale lock to clear, and deleting .state/lock unsticks nothing because nothing is stuck.
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
// elsewhere. It is an ANSWER: the question was asked and the answer is "somebody else has it".
var ErrBusy = errors.New("another mythical-ctl operation is in progress")

// ErrLockFailed is the REFUSAL, and it is deliberately a different error from ErrBusy.
//
// AN ANSWER AND AN INABILITY TO ANSWER MUST NOT WEAR THE SAME WORDS — the invariant this whole
// tree is built on. `flock` fails for reasons that have nothing to do with contention: ENOTSUP or
// EOPNOTSUPP on a filesystem that does not implement it (some network mounts), ENOLCK when the
// system's lock table is exhausted, EBADF, EINTR. Every one of those used to be reported as
// "another operation is in progress ... try again when it finishes", which is FALSE and, worse,
// actionable in the wrong direction: no other operation exists, so the operator retries for as
// long as they are willing to. A stale `pid=` body left in the lock file from an earlier run made
// the false answer more convincing still, by naming a process to go and wait for.
//
// Both refuse, and neither proceeds — the safety outcome is identical, which is exactly why this
// went unnoticed. What differs is what the operator is told to DO about it.
var ErrLockFailed = errors.New("the family lock could not be acquired")

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
	if err := flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// CONTENTION IS EXACTLY TWO ERRNOS, and nothing else may borrow their message.
		// LOCK_NB reports an already-held lock as EWOULDBLOCK, which is EAGAIN on every platform
		// this builds for; both are named because the pair is the contract, not the numeric
		// identity. The pid is read ONLY on this branch: it is a hint about a holder, and there is
		// no holder to hint at when the call never got as far as asking.
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			holder := readHolderPID(f)
			f.Close()
			if holder != "" {
				return nil, fmt.Errorf("%w (pid %s) — try again when it finishes", ErrBusy, holder)
			}
			return nil, fmt.Errorf("%w — try again when it finishes", ErrBusy)
		}
		f.Close()
		return nil, fmt.Errorf("%w: locking %q failed (%v). This does NOT mean another operation "+
			"holds it — the lock could not be taken at all, so retrying will not help by itself. "+
			"Check what kind of filesystem %s is on; some do not implement file locking", ErrLockFailed, path, err, home)
	}
	// Ours. Stamp the diagnostic body (never authorization — the flock is that).
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(fmt.Sprintf("pid=%d\n", os.Getpid())), 0)
	return &held{home: home, f: f}, nil
}

// flock is unix.Flock, indirected ONLY so a test can produce the operational failures that no
// portable test can provoke for real — a filesystem without lock support, or an exhausted system
// lock table. Nothing in the package reassigns it; the seam exists because the alternative is an
// unexercised branch in the one place that decides whether the operator is told to wait.
var flock = unix.Flock

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
func concrete(h Held) *held {
	// EXACT dynamic type, nothing else (wave-1 gate): an embedding wrapper — even one carrying
	// a real token it would faithfully delegate to — is refused outright. Delegation was
	// arguably harmless (the wrapper could not alter the inner token's home), but "only the
	// value Acquire returned is a token" is a rule with no judgment calls in it, and the
	// type assertion cannot panic on a nil-inner wrapper the way a promoted method call did.
	t, ok := h.(*held)
	if !ok || t == nil || t.released {
		return nil
	}
	return t
}
