# The `.conf` file format

`mythical-ctl` reads and writes two kinds of configuration file. This document is the contract a
product's own UI implements when it writes its settings file. It is normative: a file that does not
follow it is rejected, and rejection is not a bug.

## The two files

| | `~/.mythical/mythical.conf` | `~/.mythical/<product>.conf` |
|---|---|---|
| Who writes it | the operator, or `mythical-ctl` | the operator, `mythical-ctl`, or the product's UI |
| Mounted into a container | **never** | yes — as a single file, read-write |
| Mode | 0600 | 0660 (0600 if the family group cannot be set) |
| Integrity marker | no | **yes**, required |
| Whole-file size ceiling | none | **1048576 bytes** |
| Holds | host secrets and the launch spec | that product's own settings |

A product's UI writes **only** `<product>.conf`. `mythical.conf` is not mounted into any container,
and no value in `<product>.conf` ever reaches a container-launch argument.

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

| Situation | Result |
|---|---|
| Marker matches | accepted |
| Marker **absent or mismatched** | treated as **torn**: defaults are used, and the operator is told both what to do if they edited the file by hand and what it means if they did not |
| Marker correct but **UPPERCASE** | mismatched, therefore **torn** — the comparison is a literal string compare |
| Marker line has trailing text (a space, a second field) | mismatched, therefore **torn** |
| A marker-prefix line anywhere but the final line | rejected as malformed |
| Marker matches but the body is not valid config | rejected as malformed — the bytes are intact, so this is not damage |

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
