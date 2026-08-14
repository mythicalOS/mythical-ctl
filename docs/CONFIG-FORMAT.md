# The `.conf` file format

`mythical-ctl` reads and writes two kinds of configuration file. This document is the contract a
product's own UI implements when it writes its settings file. It is normative: a file that does not
follow it is rejected, and rejection is not a bug.

The layout holds one further configuration path, `~/.mythical/<product>/cli.toml`, which is **not**
a `.conf` file and which `mythical-ctl` never parses or validates (`backup` copies its bytes; that
is the only path here that reads them). It is specified in
[its own section below](#amendment-the-host-tool-slot-mythicalproductclitoml), and nothing else in
this document applies to it.

## The two files

| | `~/.mythical/mythical.conf` | `~/.mythical/<product>.conf` |
|---|---|---|
| Who writes it | the operator, or `mythical-ctl` | the operator, `mythical-ctl`, or the product's UI |
| Mounted into a container | **never** | to be mounted, as a single file, read-write |
| Owner | the user running `mythical-ctl` | the user running `mythical-ctl` |
| Mode | 0600 | 0660 — see [When the mode and group cannot be set](#when-the-mode-and-group-cannot-be-set) |
| Group | not constrained — 0600 makes it irrelevant | the family group |
| Integrity marker | no | **yes**, required |
| Whole-file size ceiling | none | **1048576 bytes** |
| Key-count ceiling | **1024 keys** | **1024 keys** |
| Holds | host secrets and the launch spec | that product's own settings |

### What `<product>` may be

`<product>` becomes part of a pathname, so it is validated before it becomes one. It must match

```
[a-z][a-z0-9-]{0,63}
```

— a lowercase letter, then lowercase letters, digits and hyphens, at most 64 characters — and the name
**`mythical` is RESERVED** and always refused.

Both halves matter to anyone implementing this contract. The grammar contains no path separator, no
dot, and no way to spell `..`, so a name can never escape `~/.mythical/`. The reservation exists
because `~/.mythical/mythical.conf` is the **host-only** file: treating `mythical` as an ordinary
product name would aim a product write at the file the whole host/container split depends on being
unreachable from the product side. `mythical-ctl` refuses that name, prints no path for it, and creates
nothing — an implementation that did not would corrupt the family configuration while looking correct.

Names that are refused, and are worth testing against: `mythical`, `Brokkr` (uppercase), `a b` (space),
`-lead` (leading hyphen), `a.b` (dot), the empty string, `..`, `.`, `../outside`, `bin/x`, `x/../y`, and
anything over 64 characters. `brokkr`, `skuld`, `saga`, `my-product`, `a` and `a1` are all valid.

A product's UI writes **only** `<product>.conf`.

**What is shipped, and what is design.** Everything this document says about the *file format* is
implemented and tested today: the two paths, the syntax, the byte policy, the ownership and identity
requirements, the typed validation, the integrity marker, and both size ceilings. The **runtime**
around it is not — this version of `mythical-ctl` mounts nothing and launches no container, because
the lifecycle commands are not implemented yet. So read the mounting, and the guarantees that
`mythical.conf` will never be mounted and that no value in `<product>.conf` will ever reach a
container-launch argument, as the design this format exists to serve rather than as behaviour you can
verify against this release. They are stated here because they are *why* the format is shaped the way
it is — why `<product>.conf` must be written in place, why it needs a marker, and why its size is
treated as attacker-controlled. Nothing here should be read as a delivered security guarantee.

## Amendment: the host-tool slot `~/.mythical/<product>/cli.toml`

**This section amends the layout's ownership zones**, and is where they are written down normatively
for an outside implementer. Until it, the rule was flat: a **top-level** `*.conf` was
user-owned, and *every* nested path under `~/.mythical/` — anything with a separator in it — was
installer-managed, meaning generated artifacts the installer owns and may regenerate or remove. The
amendment carves one leaf out of that zone and nothing else. Every other nested path keeps the class
it had.

### The slot

```
~/.mythical/<product>/cli.toml
```

Exactly that: the reserved leaf name **`cli.toml`**, directly inside a product's directory, one
level down and no deeper. `<product>` is the same grammar as everywhere else here
([What `<product>` may be](#what-product-may-be)), so `mythical` is reserved and
`~/.mythical/mythical/cli.toml` is not a slot.

It is the **general** case, not a per-product favour. The name is the same for every product, and
`mythical-ctl` will never generate a file at that name for any product in any version — the name is
reserved family-wide. A host-side tool that needs *more than one* file does not get to assume a
second name: that is a further amendment, not an extension a tool may make for itself.

**Three product names cannot carry a slot, and this is a limit rather than an oversight.** The
grammar above admits `bin`, `logs` and `transcripts` as product names, but those three directories
already mean something else directly under `~/.mythical/`: `bin/` is the installer's own, and
`logs/` and `transcripts/` are the user-data trees. Their zones are decided before the slot is
considered, so `~/.mythical/bin/cli.toml` stays installer-managed and
`~/.mythical/logs/cli.toml` stays user-data. That collision is older and wider than this amendment —
a product named `logs` collides with the user-data tree whatever it puts in there — and it is not
resolved here, because doing so would mean changing what is a legal product name, which is a
different contract. A host-side tool for a product with one of those three names has **no** slot
under this amendment. No product in the family is so named.

The **directory** `~/.mythical/<product>/` is unchanged — still installer-managed. Only the
`cli.toml` leaf inside it changes class.

### What a host-side tool is, and why neither `.conf` file fits

A host-side tool runs on the host beside `mythical-ctl` — a product's own CLI, for instance — rather
than inside that product's container. Its configuration is neither of the two things the layout
already had a home for. It is not *product settings*: the product never reads it, and the product's
UI must not write it. It is not an *installer artifact*: nothing in `mythical-ctl` produces it.

Putting it in `~/.mythical/<product>.conf` would be actively wrong, not merely untidy. That file is
specified above to be **bind-mounted into that product's container, as a single file, read-write**.
A host-only credential — the bearer token such a tool holds — placed there is handed to the
container by design, and *stays* handed over after a container compromise, because the container can
rewrite it as well as read it. The host-tool slot is never mounted into anything, and that is the
whole reason it exists.

`~/.mythical/mythical.conf` is host-only and would be safe in that respect, but it is the **family**
file: one shared, core-owned keyspace that `mythical-ctl` itself writes. A per-tool configuration is
not family configuration, and several tools sharing one flat keyspace is a collision waiting to
happen.

### Ownership, mode, and identity

| | `~/.mythical/<product>/cli.toml` |
|---|---|
| Ownership class (`mi_zone`) | **`user-owned`** — the same class as the two `.conf` files |
| Who writes it | the operator, or that product's host-side tool running **as the operator** |
| Mounted into a container | **never by name** — no manifest, policy or operator bind can name it; see the limit below |
| Owner | the user running the host-side tool, which is the user running `mythical-ctl` |
| Mode | **0600** |
| Group | not constrained — at 0600 no group has access, so whichever one the file lands in is fine |
| Format | the tool's own (TOML). `mythical-ctl` does not parse or validate it |
| Integrity marker | no — nothing here interprets it, so there is nothing here to detect a tear against |
| Size ceiling | none imposed by this document |

**0600, and specifically not the 0660 + family group that `<product>.conf` uses.** That combination
exists so the *container* can write its own settings file; applying it here would hand away the one
property the slot is for. What is forbidden is the *arrangement* — a group-readable or
group-writable mode, whichever group it names — not membership of any particular group: at 0600 the
group is inert, so a file that lands in the operator's primary group, or in the family group, is
equally fine. A host-tool slot found group- or world-readable should be treated as compromised —
rotate whatever it holds.

**The identity requirements are the same shape as for the `.conf` files**, and for the same reasons
given in [Ownership and identity](#ownership-and-identity): a regular file, not a symlink, link
count exactly 1. A tool that finds otherwise should refuse rather than read; a hardlink is a second
name for the same inode and passes every symlink test.

The containing directory is created by whichever side needs it first, mode **0700**, and neither
side widens it. The file's own 0600 is the guarantee that does not depend on the directory's mode.

**The limit on "never mounted", stated plainly.** The core-fixed mount set is closed and does not
name the slot, and every operator-configurable bind is refused when its canonical source is, is
inside, or contains the family home — so nothing can mount this file *by naming it or anything above
it*, and a symlink pointing back inside is refused because the check canonicalizes first. What that
check does **not** do is compare object identity: it works on pathnames, so a **hard link** to this
file created outside `~/.mythical/` has a canonical path that is genuinely outside the home and is
accepted as a bind source, which mounts the same inode read-write. This is the same gap, and the
same reasoning, as the [Ownership and identity](#ownership-and-identity) section already describes
for `<product>.conf` — which is why *that* file's link count is checked. It is **not** specific to
the host-tool slot: `mythical.conf`, holding the bootstrap secrets, is reachable exactly the same
way, and was before this slot existed. Treat "never mounted" as "never mounted by name, on a machine
where nobody has hard-linked out of your home directory", and note that creating such a link
requires write access to the directory holding the file in the first place.

`mythical-ctl` enforces none of the owner, mode, group or identity rules above, because it never
opens the file. They are requirements **on the host-side tool**, written here so that every such
tool implements the same ones. What `mythical-ctl` does guarantee is the next section.

### What `mythical-ctl` may do to it: nothing but copy it into a backup

It does not create it, modify it, move it, change its mode or ownership, or delete it, and it never
parses or interprets its contents. **It is not true that nothing here ever reads the bytes**, and the
one path that does is named in full below: `backup` copies the whole home tree. That is the only
read, it is a copy rather than an interpretation, and it is stated here rather than glossed because
"the installer never reads it" would be a false guarantee about a file holding a credential.

Pinned by tests today, and named exactly: a first `install`, a re-install over a populated home,
`stop`, `start`, `restart`, `recreate`, `uninstall --purge`, and `uninstall --family --purge` — the
two destructive verbs at their most destructive — leave it **byte-identical and at the mode it
already had**. The rule is not limited to that list; it binds every verb, including ones not yet
written.

That is a change in what the installer is *permitted* to do, not only a description of what it does
today. Installer-managed means the installer may remove what it put in there, and
`~/.mythical/<product>/` is still installer-managed. **It may not remove that directory wholesale.**
Any future code that reaps generated artifacts must delete the artifacts it created **by name**, or
skip every entry whose `mi_zone` class is `user-owned` — never `rm -rf` the product directory. No
such reaper exists in this release; the rule is written down before one does.

Two honest exceptions, neither of them a deletion:

- **`backup` reads it and copies it.** A backup walks the whole `~/.mythical/` tree and copies every
  file in it, so the slot — and the credential in it — is inside the backup, exactly as
  `mythical.conf`'s host secrets already are. **Treat a backup as secret material and give it the
  protection you would give the token itself.** It is deliberately not excluded: a backup that
  silently omitted the operator's own configuration would be a worse failure than one that includes
  it, because it would restore to a machine that looks complete and is not. `restore` does not write
  that tree back onto the machine; it restores the named volumes and the installer state ledger, and
  the captured tree is a record.
- **First use notices the directory, and is not confused by it.** A machine with no installer state
  ledger is swept for traces of a previous installation, and a product *directory* is one such
  trace. A product directory holding **nothing but** its host-tool slot is not: the host-side tool
  can legitimately be installed and configured before `mythical-ctl` ever runs on that machine, and
  refusing the first install over a file the operator meant to create would be a false alarm with a
  misleading remedy. Anything else in there is still a trace — a generated artifact, a hidden file,
  a subdirectory, an empty product directory, a symlink standing where the directory should be, or
  anything at the slot's own name that is not a plain regular file (a directory, a symlink, a
  dangling symlink) — and the install still refuses and names `state repair`. A directory that
  cannot be read is a trace too: "I could not look" is not "there is nothing there".

  **That exemption is not a validation of the file, and must not be read as one.** It asks whether a
  directory is evidence of a previous *installation*, and it decides on an entry's NAME and TYPE
  only. It does not check the owner, the mode or the link count, and deliberately does not: a
  `cli.toml` at mode 0644 is a host-tool config with the wrong permissions, not a trace of an
  installer that was here, and reporting it as an inconsistent home would send an operator to
  `state repair` over a `chmod` problem. The ownership requirements above are requirements on the
  host-side tool; nothing in `mythical-ctl` enforces them, here or anywhere.

### How the classification is spelled, and what it does not check

`mi_zone` classifies a **home-relative path**. It answers `user-owned` for `<component>/cli.toml`
exactly when `<component>` is a single path component that satisfies the
[product-name grammar](#what-product-may-be) in full — so the reserved `mythical` is refused, and so
are `Brokkr/`, `1foo/`, `-foo/`, `fooBAR/`, `foo.conf/`, `foo bar/`, a 65-character name,
`.hidden/`, and `../`. Everything else nested keeps the class it always had.

The grammar is **asked of its one authority** (`_mi_conf_product_name_ok`) rather than restated
here, so the layout cannot end up holding a second copy of it to drift against. An earlier revision
of this amendment stopped at the first character and documented the rest as an accepted overmatch;
that was wrong, because `user-owned` is a class that says "the installer does not own this", and no
path outside the carve-out is entitled to it.

Two consequences worth stating, because neither is visible in the pattern:

- **It fails closed when the authority is not loaded.** `mi_zone` lives in a module that is sourced
  before the one holding the validator, and a caller may have sourced it alone. With the validator
  absent the answer is `installer-managed` — the class the path carried before the carve-out — so an
  unanswerable question yields the unprivileged class rather than silently granting the other one.
- **The uppercase refusal depends on `LC_ALL=C`, which `_mi_conf_product_name_ok` — the grammar's
  authority, and the only place a character range still decides anything — pins for itself.** Under
  a dictionary-collating locale `[a-z]` matches uppercase, so without it a path would classify one
  way on an operator's laptop and another in CI. Measured on the bash 3.2 floor. `mi_zone`
  deliberately carries no second copy of that pin: with the authority behind it, a copy would decide
  nothing and could be removed with nothing going red.
- **Bash's `nocasematch` is defended against, on both halves.** `case` honours that option, so with
  it enabled `brokkr/CLI.TOML` would otherwise reach the slot arm — hence the leaf being compared as
  a string rather than matched as a pattern. The option also changes how the grammar's own `case`
  matches (measured: `_mi_conf_product_name_ok Brokkr` succeeds under it), so the validator is called
  with the option unset. It is worth knowing that this is reachable from the *environment*:
  `BASHOPTS=nocasematch` does not arm it, but `BASH_ENV` naming a file that sets it does, for every
  non-interactive shell. That reachability is a property of the whole CLI, not of this slot — every
  other `case` in it is still affected — and closing it generally is not something this amendment
  attempts.

Read the classifier's answer as a statement about the path, never as permission to create one.

The depth rule is load-bearing and is not visible in the pattern, so it is worth saying where it
lives. `case` globs match `/`, so the arm that catches candidates also catches
`brokkr/generated/cli.toml` and `../cli.toml`. What refuses them is the same exact comparison that
defends the leaf's spelling: the remainder after the FIRST separator must equal `cli.toml`, and for
anything deeper that remainder still contains a separator (`generated/cli.toml`) and cannot. The
traversal spellings are then refused a second time over by the grammar, which does not admit `..`
or `.` as a product name. One comparison, three rules, and no arm that merely looks like a guard.

## Ownership and identity

`mythical-ctl` checks **what the path is**, not only what it contains, and refuses it if any of the
requirements below is not true. These are as normative as the syntax: a file that fails one is rejected
with the file left untouched — no partial write, and no fallback to defaults either, because this is a
refusal and not a torn-file report.

**What the check does and does not promise.** It describes the pathname *at the moment it runs*. That
is a real limit, not a hedge. Shell can hold a file descriptor open — that is not the problem. What
portable shell lacks is the sequence needed to *bind* the checked identity to the object it then
operates on: opening with `O_NOFOLLOW`, verifying the open descriptor itself, and writing through that
same descriptor. Every step here works on the pathname instead, so between the last check and the
operation the pathname can in principle be replaced. `mythical-ctl`
re-checks immediately before every mutation to make that window as small as the language allows, and a
family operation lock excludes every other `mythical-ctl` process — but the window is not zero, and
closing it would need file-descriptor- or mount-namespace-based I/O that portable shell does not have.
Read these requirements as "this path is refused when it is seen to fail", not as an unconditional
guarantee about the object finally written. Nothing else in this document depends on the difference.

Where the check runs, exactly, because it is not symmetrical:

- **`<product>.conf` — on every read and every write.** It is the bind-mounted, container-writable
  file, so its path is the one an attacker can reshape.
- **`mythical.conf` — before every write.** It is host-only and never mounted, so the check is
  hardening rather than a boundary; reading it goes through the generic reader, which does not repeat
  it.

| Requirement | Why |
|---|---|
| **Owned by the user running `mythical-ctl`** | The owner is the only identity that can reliably set the mode and group afterwards. A file owned by someone else can still be *writable* by us — on a rootful container runtime with no userid remapping, a compromised container can `chown 0:0 <product>.conf; chmod 0666` — so without this check the content write succeeds and only the `chgrp`/`chmod` fail, leaving a rewritten file that is root-owned and world-writable. |
| **A regular file** | A fifo or device node is not a configuration file, and reading one can block forever. |
| **Not a symlink** | Following one writes to a path of whoever planted the link's choosing, and *reads* the link target's content as though it were this product's configuration. |
| **Link count exactly 1** | A hardlink is a second name for the **same inode**, not a link at the path level, so every symlink test passes it. `brokkr.conf` hardlinked to `mythical.conf` turns a product write into a write to the host-only file; hardlinked to the CLI it rewrites the CLI. This installer created the file, so nothing legitimately shares its inode. |

**This is the rule most likely to surprise an implementer**, because none of it is visible in the
file's bytes. Any path that produces the file as a *different* user yields a permanent rejection that
nothing in the content explains — a UI that creates the file as a service account, a recovery
procedure run under `sudo`, a restore from a tarball unpacked by another user, or a `cp` performed as
root.

**The remedy is to fix the ownership, not the content**: `chown <operator> ~/.mythical/<product>.conf`
(and remove any extra hardlink to it, or replace the symlink with a real file), then re-read. If the
file's content is intact it will load unchanged. A UI creating the file for the first time should
create it **in place, as the operator**, rather than writing it elsewhere and moving it in.

### When the mode and group cannot be set

`<product>.conf` is meant to end up **owned by the operator, mode 0660, group = the family group** —
that combination is what lets the product's own settings screen write the file while nobody else can.
Setting the group requires the operator to be *in* that group, and that is not always true on the
machine where the write happens.

When it is not, the write still lands — the bytes and the marker are committed — but the file does
**not** carry the ownership above, and `mythical-ctl` reports that as a distinct outcome:
**written, but not to the documented ownership spec.** It is not a success, and it is not a refusal.
There are exactly three shapes of it, and the message says which:

| State | What is true | What the operator has to do |
|---|---|---|
| The group could not be set | Mode was forced to **0600** — deliberately, because 0660 owned by the operator's *primary* group would grant unrelated local users access while granting the container none. | Add the operator to the family group and run the same command again; a repeat write with the same values changes no bytes and re-applies the mode and group. |
| The group **was** set, mode 0660 was not | The group is correct. Only the mode is wrong, and the file is at whatever mode it already had. | `chmod 660` the file. Nothing is wrong with the group. |
| Neither the group nor the 0600 fallback could be applied | The mode is **neither** 0660 nor 0600 and has to be inspected. | Check the mode and ownership by hand before relying on the file. |

A caller must not collapse these into one message. "The family group could not be set" is a false
diagnosis in the second row, where the group is exactly right.

## Syntax

- Text. Every line ends with `\n`, **including the last** — a file not ending in a newline is
  treated as truncated. `mythical.conf` is then refused outright; `<product>.conf` is reported as
  **torn** and the reader falls back to defaults (see the marker section, which treats a cut-off last
  line exactly as it treats a missing marker, because they are the same accident).
- **Byte policy:** no control bytes anywhere (no NUL, CR, TAB, DEL — the only permitted control byte
  is the `\n` that ends each line). Every other byte is passed through verbatim, **including bytes
  ≥ 0x80**. The reader does *not* validate UTF-8 and does not need to: it never decodes a value, and
  refusing a home directory such as `/Users/José/work` would break real operators for no gain. Write
  UTF-8 if you have a choice; a non-UTF-8 byte sequence is accepted rather than rejected.
- Blank lines and lines beginning with `#` are ignored (the marker is a `#` line; see below).
- Every other line is `KEY=VALUE`, split on the **first** `=`. A value may contain further `=`.
- Keys match `MYTHICAL_[A-Z0-9_]+`, at most 128 characters. A key not in the product's schema is
  **rejected, not ignored** — the whole file fails to load.
- A duplicate key is rejected as ambiguous.
- Values: at most 4096 **bytes** (bytes, not characters — a 2049-character accented value is 4098
  bytes and is refused); no leading or trailing space; no control characters at all (no NUL, no
  CR, no TAB); and none of `$`, `` ` ``, `\`. Any other printable character is allowed, and so is any
  non-ASCII (UTF-8) content.
- There is **no quoting and no escaping**. A value is the literal bytes between the first `=` and the
  end of the line. Do not wrap values in quotes — the quotes become part of the value.

The file is never `source`d, `eval`d or shell-expanded by anything that reads it, so `$(…)` and
`` `…` `` are inert. They are refused anyway, so that a reader never has to reason about it.

## Values are additionally validated against a type

Obeying every rule above is **necessary and not sufficient.** After the syntax passes, each key's
value is checked against a **type**, declared for that key by the schema the product ships. A file
that is syntactically perfect is still rejected wholesale if any value does not fit its type — an
over-long `str:`, an `int:` with a leading zero, an `enum` value containing `|`.

The types, and the rules an implementer would not guess:

| Type | Accepts | The non-obvious part |
|---|---|---|
| `str:<maxlen>` | any permitted value, up to `<maxlen>` | `<maxlen>` is **bytes**, like the 4096-byte value cap: a 5-character accented value is 10 bytes. |
| `int:<min>:<max>` | decimal digits, within the inclusive range | **Non-negative only.** No sign, no leading `+`, no surrounding space — and **no leading zero**, because a leading zero would be re-read as *octal* and `010` would compare as 8, letting a textually out-of-range value validate. `0` on its own is fine. Signed values are not supported at all; a schema writing `int:-10:10` is a schema bug, not a value that should validate. |
| `enum:<a>\|<b>\|<c>` | exactly one listed member | A member **cannot contain `\|`**: it is the separator and the format has no escaping. A value containing one is refused rather than matched. Comparison is exact — not a prefix, not a substring, and the empty value is never a member. |
| `bool` | exactly `true` or `false` | Nothing else. Not `1`, `0`, `yes`, `on`, or `True` — the comparison is case-sensitive. |
| `path:<maxlen>` | an absolute path, up to `<maxlen>` bytes | Must start with `/`, and must contain **no `..` component**. A `..` inside a *name* is fine: `/srv/..hidden` is a legitimate path, `/srv/../etc` is not. |
| `netname` | a container-network name: `[A-Za-z0-9]` then `[A-Za-z0-9_.-]*` | Additionally refuses `host`, `none` and `container:<name>` — those are network *modes*, not networks this installer may own. |

Every one of these is evaluated in byte order, so the same file validates identically whatever locale
the reader is running under.

**The schema itself is not part of this document.** Which keys exist for a product, and which type
each one carries, is declared by that product and can change with it; this section fixes only what
each type *means*. `mythical.conf`'s own keys are core-owned.

## The integrity marker

`<product>.conf` ends with **exactly one** marker line, and it must be the **final** line. A line
beginning with the marker prefix anywhere else in the file is rejected — there is no such thing as a
"marker comment", and allowing one would let a second marker sit in the body where no reader agrees
on which is authoritative. The same rule applies to `mythical.conf`, which carries no marker at all:
one scanner reads both files, and it refuses a marker-prefix line anywhere except as the final line
of a `<product>.conf`.

The marker line is:

```
#mythical-conf-sha256=<64 lowercase hex characters>
```

The value is the SHA-256 of **every byte of the file above that line**, including the final newline
of the last body line, and excluding the marker line itself.

Nothing may follow the hex on that line. The reader takes the whole remainder of the line as the
digest, so a trailing space, a comment, or a second field makes the file read as torn.

### The digest domain is BYTES, not lines

This is the rule to implement, stated on its own because it is the one an implementer is most likely
to get subtly wrong while producing a file that looks perfect.

The domain is a **byte range**: from offset 0 up to — and not including — the first byte of the
marker line. It is *not* "the body lines, joined with newlines". That idiom is short by exactly one
byte, because it drops the `\n` that terminates the last body line, and the resulting digest is a
valid-looking 64-hex-character string that will never match. A product UI built that way writes
files that read as torn **forever**, with nothing visibly wrong with any of them.

Measured, on this 56-byte body:

```
MYTHICAL_BROKKR_RETENTION=30
MYTHICAL_BROKKR_THEME=dark
```

| what was hashed | digest |
|---|---|
| all 56 bytes — **correct** | `dfdaa4bd5c6dacbfdfd131728e3643f8d21b84d9f7d909851bdbd8761b36d35f` |
| the same bytes minus the final newline (55 bytes) — wrong | `7c359dde1be9bd6393285711b54e2904ee67d53858ba545c15ed8c1e8bbcdab5` |

So: hash the bytes you are about to write, or the bytes you just wrote. In a language with a
byte-oriented digest API, feed it the same buffer you hand to `write()`. Do not reconstruct the body
from a list of lines unless you re-append the final terminator.

### The hex must be lowercase

The reader compares the 64 characters after the prefix to its own digest as a **literal string**. It
does not canonicalise case, and it does not parse the hex into bytes. The uppercase form of a
*correct* digest is therefore a mismatch, and the file reads as torn — verified, not assumed.

`sha256sum` and `shasum -a 256` both emit lowercase, so the shell recipes below are safe as written.
A language library is the hazard: some hex encoders default to uppercase, and some
`byte.toString(16)`-style idioms produce it. Lowercase the digest before writing it.

### A marker-only file is valid

Zero body lines is a legal configuration. The marker is then the SHA-256 of the empty byte string:

```
#mythical-conf-sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

That file loads successfully as an empty configuration — no keys set, no error. A product UI that has
nothing to persist yet should write this rather than an empty file or no file, because it is the one
form that says "intentionally empty" in a way the reader can verify.

An **empty (zero-byte) file is not the same thing and is not valid**: it has no marker, so it reads
as torn, exactly like a write that died before reaching the marker. That is the correct outcome —
those two situations are indistinguishable from the bytes, and the fail-closed reading is the safe
one.

### Reference implementation

Shell; `sha256sum` on Linux, `shasum -a 256` on macOS — neither is POSIX, so probe for them:

```sh
# body.txt holds the KEY=VALUE lines, each terminated by a newline, and nothing else.
# Hash the BYTES OF THE FILE. Do NOT do `body=$(cat body.txt)` and hash "$body":
# command substitution strips trailing newlines, so that hashes different bytes than the
# file contains and the marker will never match.
sha256sum < body.txt | cut -d' ' -f1        # Linux
shasum -a 256 < body.txt | cut -d' ' -f1    # macOS
```

Equivalently, given the finished file, the marker is the digest of everything except its last line:

```sh
sed '$d' <product>.conf | sha256sum | cut -d' ' -f1
```

### How a mismatched marker is treated

**Order matters, so read this before the table.** The checks do not all have equal standing; they run in
a fixed order, and the first one to fail decides the outcome:

1. **Is the file there at all?** An absent `<product>.conf` is **absent**, not torn. It is the ordinary
   state before anything has been configured — no defaults-with-a-warning, no damage report.
2. **Is it within the size ceiling?** A file at or over 1048577 bytes is **rejected as malformed**, and
   this happens before any byte of it is examined — the reader copies a bounded prefix and refuses if
   that prefix comes back full, so it never holds an oversized file at all. An oversized file that
   *also* contains a control byte is reported as oversized, not as a byte-policy failure.
3. **Does it obey the byte policy?** A file containing a control byte (NUL, CR, TAB, DEL) is **rejected
   as malformed**, whatever its marker says. This is checked *before* the marker, so a NUL-bearing file
   with no marker is malformed — not torn. Hostile or binary content is not a damaged config.
4. **Does it end in a newline?** If not, the last write was cut mid-line: **torn**.
5. **Does the marker match?** Only now. Absent or mismatched ⇒ **torn**.
6. **Does the body parse and satisfy the schema?** If not, **rejected as malformed** — the bytes are
   intact, so this is not damage.

So "torn" means specifically *byte-clean content whose marker does not vouch for it*. Anything that
fails an earlier gate is a refusal instead, and the two must not be conflated: a refusal means fix or
remove the file, while torn means the settings fall back to defaults and the file wants its marker
recomputed.

| Situation | Result |
|---|---|
| File absent | **absent** — the normal unconfigured state, not torn and not an error |
| Contains a control byte (NUL, CR, TAB, DEL) | **rejected as malformed**, regardless of the marker |
| Does not end in a newline | **torn** — the last write was cut mid-line |
| Marker matches | accepted |
| Marker **absent or mismatched** | **torn**: defaults are used, and the operator is told both what to do if they edited the file by hand and what it means if they did not |
| Marker correct but **UPPERCASE** | mismatched, therefore **torn** — the comparison is a literal string compare |
| Marker line has trailing text (a space, a second field) | mismatched, therefore **torn** |
| Present but zero bytes | **torn** — a file with no marker at all |
| A marker-prefix line anywhere but the final line | rejected as malformed |
| Marker matches but the body is not valid config | rejected as malformed — the bytes are intact, so this is not damage |
| Marker matches but a value fails its type | rejected as malformed — same reason |

A write torn at a line boundary produces a file that parses perfectly and is missing every setting
after the cut. That is why a mismatch is not forgiven just because the remaining text is well
formed.

**If you edit this file by hand, recompute the marker afterwards** with the recipe above — otherwise
the next read reports it as damaged and falls back to defaults.

The marker detects a torn write. It is **not** an authentication mechanism: a process that can write
the body can write the marker. The parser and its schema are the security control.

## The whole-file size ceiling

A `<product>.conf` larger than **1048576 bytes (1 MiB)** is **refused outright, before parsing** —
not treated as torn, and not partially read. The boundary is inclusive: a file of exactly 1048576
bytes is accepted, and 1048577 bytes is refused.

The ceiling exists because this is the one file in the layout that is bind-mounted **read-write into
a container**, which makes its size attacker-controlled after a container compromise. The per-value
4096-byte cap does not help: it bounds *one value*, not the number of values, the number of comment
lines, or the size of the file. Without a whole-file bound, reading it would mean copying an
arbitrary number of bytes into host storage and then building the whole body in memory.

`mythical.conf` has no such ceiling. It is never mounted, so its size is not attacker-controlled;
the only writers are the operator and this CLI.

1 MiB is far beyond any legitimate configuration — at the 4096-byte value cap it is hundreds of
settings.

## The key-count ceiling

A file containing **more than 1024 assignments is refused**, before any of them is used, with a
message naming the cap. The boundary is inclusive: 1024 keys is accepted, 1025 is refused. Unlike the
size ceiling, this applies to **both** files.

It is a separate limit because the size ceiling bounds the *bytes* a reader copies, not the *work* it
does. The duplicate-key check is quadratic in the number of keys, so a file well inside 1 MiB can cost
minutes of CPU: measured, 14000 short valid keys is 240 KB and took 22 seconds, and 20000 keys is
349 KB and took 46. Since a mutating write holds the family operation lock while it reads, an
oversized-by-key-count file would block every other product's install or reconfigure for as long as
it took to parse.

1024 is far above anything legitimate for the same reason 1 MiB is: 1 MiB divided by the 4096-byte
value cap is about 256 maximal settings. If a product genuinely needs more than a thousand keys in one
file, it needs a different storage mechanism, not a larger config file.

## Writing safely

- Refuse to write a value containing a newline. Without that check, a value can forge a second
  `KEY=VALUE` line on the next read.
- **Write body and marker as one `write()`, with the marker as the final line.** Build the whole
  file — body bytes followed by the marker line — in memory, and emit it in a single operation. Do
  not append incrementally, and do not write the body and then the marker as two separate writes:
  that is two chances to tear instead of one. What matters is that the marker's bytes are *last in
  the byte stream*, because that is what makes a truncated write detectable — a write cut short loses
  the marker, or leaves a stale one, and either way the digest does not match.
- Never replace the file by `rename()`/`mv` — it is bind-mounted, and replacing the inode detaches
  the mount silently.

## This document's path is part of the contract

When `mythical-ctl` reports a `<product>.conf` as torn, the message it prints to the operator names
this file **by path**:

```
  If you edited it by hand, recompute the marker (see docs/CONFIG-FORMAT.md);
```

So `docs/CONFIG-FORMAT.md` is not merely where this document happens to live — it is a string in
shipped runtime output. Moving or renaming it turns that message into a dangling pointer for every
operator who ever hits a torn file, and nothing in the build would notice. If it has to move, change
the message in the same commit.
