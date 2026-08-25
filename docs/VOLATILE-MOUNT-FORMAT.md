# The volatile credential-home mount

Some products materialize a **file-based credential** — one written to disk for a child process to
read, rather than held in memory — and they need one **isolated home per session** so concurrent
sessions never share a credential file. `mythical-ctl` gives such a product a dedicated, fully
hardened, **non-persistent** place to put those homes: a container **tmpfs**. This document is the
contract for that mount. It is the twin of the one manifest field that names it, and it is normative:
a mount that does not match it is refused rather than downgraded.

The whole purpose of the mount is **least-duration, session-private custody**. Every hardening
property below is therefore **fixed by this contract and cannot be declared** — the manifest carries
only *where* the mount lives, never *how* it is mounted. That closure is what stops the field from
becoming a general-purpose container-mount escape hatch.

## The manifest field

A product declares the mount with exactly one manifest key:

```
volatile_mount   <bounded absolute container path>
```

- **Key:** `volatile_mount` (type `cpath`; see [`DOCUMENT-FORMAT.md`](DOCUMENT-FORMAT.md)).
- **Value:** one bounded absolute container path — the mount point (the credential-home root). It is
  the *only* thing the field declares. There is deliberately **no options sub-grammar**.
- **Cardinality:** at most one. A product that materializes no file-based credential omits it.

### Path grammar (accept / reject)

A value is accepted only when it is an absolute path of safe segments:

- it begins with `/`;
- each segment matches `[A-Za-z0-9._-]+`;
- there is no trailing slash, and the bare root `/` is refused;
- there is no empty segment (no `//`);
- there is no `.` or `..` traversal segment;
- there is no whitespace or control byte;
- its length is 2..512 bytes.

Everything else is rejected: a relative path, a traversal path, a trailing slash, an empty value, a
control byte, and an over-length value. Because the accepted per-segment charset is only
`[A-Za-z0-9._-]`, the grammar also refuses any attempt to append a second token or an options list —
a space, a comma, a colon, or an `=`. **This is the closure**: a publisher cannot smuggle
`…,nodev=false` or a bind `source=` past a field that can hold nothing but a single clean path.

### The canonical production root

```
/run/mythical/credential-homes
```

Supported deployments mount **this** path as the volatile tmpfs. On the production install path the
declared root must be exactly this: production may **not** fall back to a state directory, a bind
mount, a named volume, or the container's writable layer. (A test harness may point the lower-level
machinery at a private temporary root, but the real install path enforces the canonical one.)

## The fixed mount

The declared path maps to one fully hardened mount. Every property below is fixed; none is negotiable.

| Property | Fixed value | Meaning |
|---|---|---|
| type | `tmpfs` | A container tmpfs — RAM-backed, disposable, cleared on container restart. |
| persistence | non-persistent | Never a durable bind, a named volume, or a writable-layer path. |
| `nodev` | on | No device nodes may be created on the mount. |
| `nosuid` | on | setuid/setgid bits are ignored on the mount. |
| `noexec` | on | No file on the mount may be executed. |
| ownership | daemon-owned root | The mount root is owned by the product's runtime daemon; no session identity can traverse it. |
| home directory mode | `0700` | Each isolated home directory beneath the root is `0700`. |
| credential file mode | `0600` | Each credential file inside a home is `0600`. |
| backup / restore | excluded | The mount is excluded from every backup and restore path. |

The three security flags are rendered in one canonical order — **`nodev,nosuid,noexec`** — so a
Compose tmpfs option string and the `mythical-ctl` mount invocation are byte-comparable.

A conformant mount is therefore **never** a durable bind, a named volume, a persistent mount or the
writable layer, a shared home, a mount missing any of `nodev`/`nosuid`/`noexec`, a mount with a
widened directory or file mode, or a mount included in backup or restore.

### Who establishes which property

The contract is fulfilled by **two** surfaces, and it is worth being precise about the split, because
neither can establish the whole of it alone:

- **`mythical-ctl` renders the mount kind and the kernel security flags.** It attaches a
  **non-persistent tmpfs** at the declared root carrying `nodev,nosuid,noexec`. It does **not** set an
  owner or a mode on the root, and it deliberately cannot: the identity the root must belong to is the
  product's own runtime daemon, which the installer does not run as and whose uid is the daemon's to
  know, not the installer's to guess.
- **The product's runtime daemon establishes the daemon-owned root and the modes beneath it, and
  verifies the mount before it enables file-based authentication.** At startup — *before* any session
  is spawned — it takes ownership of the root, makes it session-private, sweeps it clean, and confirms
  the mount matches this contract. A container tmpfs is created world-writable by default, so this
  daemon-side step is what actually makes the root untraversable; there is no window before it,
  because no session runs until the daemon has armed. The same verification is what catches anything
  the installer's manifest-level checks cannot see — for example a mount the **image itself** declares
  at a path beneath the root: a non-conforming mount keeps file-auth **disabled** with an
  operator-visible error rather than placing a credential on storage that does not match this contract.

## Materialization and teardown

`mythical-ctl` renders the mount at the single place it launches a container, using the mount form
that carries the kernel security flags. Because the mount is a **tmpfs**, it is non-persistent by
construction:

- **Bring-up** attaches the hardened tmpfs at the declared root. `mythical-ctl` additionally refuses
  any *manifest-declared* mount — a named volume or an operator bind — whose container target sits at,
  under, or over the root (compared on normalized paths, so an equivalent spelling cannot slip past):
  a durable mount inside the tree would shadow the tmpfs with persistent storage. The product's daemon
  then takes ownership of the root and creates the `0700` homes and `0600` credential files beneath it.
- **Teardown is a wipe.** Removing the container discards the tmpfs and everything on it — no
  credential file survives the container that used it, and there is nothing on durable storage to
  scrub. Replacing the container gives the next launch a fresh, empty root.

Because the credential homes never live on durable storage, they are **excluded from backup and
restore**: a backup preserves durable data (named volumes and the host tree), and a tmpfs is neither.

## Validating an implementation against this contract

An implementation is conformant when, given a `volatile_mount` value:

- it **accepts** exactly the paths the grammar above accepts and **rejects** every other — a
  relative path, a traversal, a trailing slash, an over-length value, and any value carrying a second
  token or an option;
- on the production path it **requires** the canonical root and refuses any fallback to durable
  storage;
- it renders a **non-persistent tmpfs** carrying exactly `nodev,nosuid,noexec`, excluded from backup
  and restore, and it refuses any *manifest-declared* mount whose target overlaps the root;
- the daemon-owned root and the `0700`/`0600` modes beneath it are established, and the mount
  verified, by the product's runtime daemon before it enables file-based authentication, as described
  above;
- it refuses any mount whose hardening is weakened — a missing flag, a reordered or added option — as
  a *different* mount rather than downgrading silently.
