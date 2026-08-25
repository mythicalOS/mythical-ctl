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

The declared path maps to one fully hardened mount. Every value below is rendered by
`mythical-ctl`; none is negotiable.

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
Compose tmpfs option string and the `mythical-ctl` mount invocation are byte-comparable. The home and
credential-file modes describe the directories and files the product's daemon creates **beneath** the
root, not the root mount itself; the root is daemon-owned so that no session identity can traverse it.

A conformant mount is therefore **never** a durable bind, a named volume, a persistent mount or the
writable layer, a shared home, a mount missing any of `nodev`/`nosuid`/`noexec`, a mount with a
widened directory or file mode, or a mount included in backup or restore.

## Materialization and teardown

`mythical-ctl` renders the mount at the single place it launches a container, using the mount form
that carries the kernel security flags. Because the mount is a **tmpfs**, it is non-persistent by
construction:

- **Bring-up** attaches the hardened tmpfs at the declared root; the product's daemon then creates
  the `0700` homes and `0600` credential files beneath it and owns the root.
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
- it renders a **non-persistent tmpfs** carrying exactly `nodev,nosuid,noexec`, daemon-owned, with
  `0700` homes and `0600` credential files beneath the root, excluded from backup and restore;
- it refuses any mount whose hardening is weakened — a missing flag, a reordered or added option — as
  a *different* mount rather than downgrading silently.
