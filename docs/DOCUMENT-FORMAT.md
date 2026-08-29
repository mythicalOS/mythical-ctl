# The authenticated document format

`mythical-ctl` accepts three kinds of document from outside the machine it runs on: a **family
index**, a **family policy index**, and a per-product **manifest**. This document is the contract
those three follow. It is written for the people who produce them and never read this repository's
source to do it: a **product author** writing a manifest, and a **family/policy publisher** signing
the family index and the policy index. It is normative — a document that does not follow it is
rejected, and rejection is not a bug.

These documents are **more privileged than `<product>.conf`**, not less. A manifest names the image
that will run, the mounts that will be made, and the secrets that will be injected. Every rule
[`docs/CONFIG-FORMAT.md`](CONFIG-FORMAT.md) places on the **bytes and values** of product
configuration binds here too — the byte policy, the value rule, the key-count ceiling — plus the
authentication and freshness rules this document adds on top. Its **integrity marker** is the one
thing that does not carry over: these documents have none. Their authenticity comes from a digest a
parent document vouches for, and a line that merely looks like a marker is an ordinary comment
here.

## Why line-oriented `key=value`, not JSON

Every document in this family — including the family index and the policy index — is the same
`key=value` text format `<product>.conf` uses, not JSON. The one JSON a *product* puts in front of
this tool is `/detect`, and that is JSON because it isn't ours: it is an existing HTTP response
from the product's own runtime, defined separately (see the note on `/detect` at the end of this
document).
Everything *authenticated* — the index, the policy, the manifest — is emitted and consumed
entirely inside this project's own tooling, so there is no external format to inter-operate with.
What the shared format buys is that these documents and `<product>.conf` pass through the **same**
byte gate and the **same** value rule rather than through two implementations of them: one audited
scanner decides what counts as a control byte and what a value may contain, for the least-trusted
input in the system and the most privileged alike. A separate grammar for the privileged documents
would be a second thing to get wrong, on exactly the inputs where getting it wrong is worst.

**This is not a claim that the tool cannot parse JSON.** `mythical-ctl` is a single static binary,
and it does link a JSON decoder — it speaks the container runtime's JSON API over the daemon
socket. The authenticated documents do not go through it, and neither does the `/detect` reader;
in both cases that is a choice, stated where it is made, rather than a missing capability.

## The three document types, and their header line

Every document starts with a mandatory first line naming its type and format version:

```
mythical-index 1
mythical-policy 1
mythical-manifest 1
```

The header is checked **after** the rest of the file is scanned but **before** anything is handed
back to a caller, so a document of the wrong type — or a document written against a format version
this build does not understand — never yields a single field to code that forgot to check the
result. A first line that doesn't match `mythical-<type> <N>` exactly, byte for byte, is rejected;
there is no sniffing and no fallback.

## Grammar

The body — everything after the header line — is line-oriented text, and nothing that reads it
evaluates, expands or executes any part of it:

- Every line ends with `\n`, **including the last**. A file that doesn't end in a newline is
  rejected as truncated.
- Blank lines and lines starting with `#` are ignored.
- Every other line is `KEY=VALUE`, split on the **first** `=`. A value may itself contain `=`.
- A key is `[a-z][a-z0-9_]*`, at most 128 bytes whole, and may carry **exactly one** dotted prefix
  of the same shape: `brokkr.permitted_role` is legal, `a.b.c` is not. This is how the policy index
  scopes an entitlement to one product without the format needing real nesting — see
  [Residual: the format cannot nest](#residual-the-format-cannot-nest). The policy index
  additionally requires the prefix to be a valid `ident` (see the types below), so a well-formed
  key whose prefix is not a product identifier is refused there as an unknown key. A key that is
  not in the document's schema is **rejected, not ignored** — the whole document fails to load, the
  same as an unknown key in `<product>.conf`.

  **The key alphabet and `ident` are not the same alphabet, and the difference is a real limit
  rather than a subtlety.** A key half admits `_` and not `-`; `ident` (and the product-name
  grammar in [`docs/CONFIG-FORMAT.md`](CONFIG-FORMAT.md)) admits `-` and not `_`. They overlap on
  `[a-z][a-z0-9]*`. So a product whose name contains a hyphen cannot be named as a prefix at all:
  `my-product.permitted_role` is refused as an invalid key name, even though `my-product` is a
  valid product name. That is measured, not inferred. No product in this family is so named, and
  nothing silently mis-grants as a result — the document is refused either way — but a publisher
  for a hyphenated product has no spelling that works, and this format cannot give them one
  without changing what a key may be.
- A duplicate key is rejected, unless the document's schema explicitly marks that key repeatable
  (`many`, below) — in which case every occurrence is kept, in order.
- At most 1024 keys per document — the same ceiling `<product>.conf` and `mythical.conf` carry.
  It is enforced **during** the scan: a document is refused at the line that crosses the cap,
  naming the cap, rather than after the whole of it has been accumulated.

### Byte and value rules (inherited from `docs/CONFIG-FORMAT.md`)

The byte policy and the value rule are **exactly** `docs/CONFIG-FORMAT.md`'s — the same check, not a
second implementation of it:

- **No control bytes** anywhere except the `\n` that ends each line (no NUL, CR, TAB, DEL). A file
  containing one is rejected outright, before the header or the schema is considered — but *after*
  the digest, which is checked before any of these bytes are inspected at all (see
  [Precedence](#precedence-the-order-these-checks-run-in)).
- **Values**: no leading or trailing space; no control characters; none of `$`, `` ` ``, `\`; bounded
  length. Any other byte is passed through verbatim, including non-ASCII (UTF-8) content — the
  reader never decodes a value, so it never needs to validate UTF-8.
- **No quoting and no escaping.** A value is the literal bytes between the first `=` and the end of
  the line. Do not wrap a value in quotes; the quotes become part of it.

If you are implementing a writer for one of these documents, read `docs/CONFIG-FORMAT.md`'s
"Syntax" section in full: it describes these same byte and value rules in more depth, with worked
examples, and they apply here unchanged. Its "Writing safely" section carries over only in part.
The rule against writing a value containing a newline applies here for the same reason — a newline
in a value forges a second assignment on the next read. The other two do **not**: these documents
have **no integrity marker** (their authenticity comes from a digest a parent document vouches for,
not from a marker line of their own — a line that merely looked like one would be an ordinary
comment here), and they are **not bind-mounted**, so the prohibition on replacing the file by
`rename()` does not apply to them either.

## Precedence: the order these checks run in

An implementer's first instinct is usually to check the checks in the order that's easiest to
write, which is not the order this format is actually verified in. The order matters because each
step's failure mode is a different, specific answer, and collapsing two into one gives an operator
the wrong diagnosis. In the order they actually run, for every document handled through this
project's acceptance path (`trust.AcceptIndex`, `trust.AcceptPolicy`, `trust.AcceptManifest`, and
their check-only siblings, which run the identical chain and commit nothing):

1. **Does the document authenticate against its digest?** This runs **first**, over the file's raw
   bytes — before the byte policy, the grammar, or the schema are applied to those bytes at all.
   (Two things do precede it, and neither inspects content: the file must be openable to be hashed
   at all, and the read that hashes it is bounded at the same 1048576-byte ceiling
   `<product>.conf` carries — a document over that ceiling is refused for being over it, before
   any digest is computed. What step 2 gates on is everything that inspects what the bytes
   actually *contain*.) The
   expected digest for an index comes from the trust anchor (see [Trust model](#trust-model)); the
   expected digest for a policy index or a manifest comes from the *already-authenticated* parent
   document (the family index) that names it. A digest that does not match is rejected immediately,
   and the bytes are **never inspected further** — only a verified copy is handed to anything that
   reads content, never the live pathname a second time. Verifying the digest before looking at the
   content is the whole point: nothing may be judged on what it says until something
   already-authenticated has vouched for its bytes.
2. **Only once the digest matches** are the bytes handed to anything that looks at their content —
   and the byte policy (readable at all; no control bytes; ends in a newline) is the *first* thing
   that content-reading step does. Then the **body**: the line grammar above, the key grammar, the
   value rule and the key-count ceiling. Then the **header line** — after the body has been scanned,
   deliberately, and before anything at all is handed back to a caller (see
   [The three document types](#the-three-document-types-and-their-header-line)). Then the document's
   own **schema**: which fields exist, their types, their cardinality. A control byte, a missing
   trailing newline, or a malformed line is rejected here — but only ever for a document that has
   already authenticated.
3. **Is it fresh?** A version is present, an expiry is present and has not passed, and the version is
   not below the highest one this installation has already accepted for that document (anti-rollback
   — see [Trust model](#trust-model)).
4. **Is it authorized?** (Manifests only.) Every role, secret, and mount the manifest selects must
   already be granted to that product by the policy index — a manifest can be perfectly authentic
   and still ask for something it was never entitled to.
5. **Does it declare compatibility?** (Manifests only.) The manifest's declared minimum core version
   must be one this build satisfies.

A document that fails any earlier step is refused for *that* step's reason, never re-diagnosed by a
later one — a document that fails step 2 is never reported as "expired," and an expired document is
never reported as "unauthorized."

**A practical consequence worth stating plainly: if you hand-edit an authenticated document, what
you get back is a digest mismatch, not a diagnosis of what you changed.** Editing a byte anywhere in
the file — fixing a typo, "cleaning up" whitespace, adding a comment — changes the bytes the digest
was computed over, so step 1 fails before step 2 ever runs. You will never see "contains control
bytes" or "line 4: invalid key name" from an edited copy of an authenticated document, even if the
edit also happens to introduce exactly that problem — you will see a digest mismatch, because that
is the first and only thing checked before anything about the edit's content is looked at. This is
not a diagnostic gap to close; it is the same property that makes authentication meaningful at all —
a check that ran on content *before* that content was proven to come from where it claims to could be
satisfied by an attacker's edit just as easily as by the operator's.

## Types

Every value, once the grammar above accepts it, is additionally checked against a **type** the
schema declares for that key. A document that is syntactically perfect is still rejected wholesale
if any value does not fit its declared type.

Types shared with `<product>.conf` (see `docs/CONFIG-FORMAT.md` for the full rules): `str:<maxlen>`,
`int:<min>:<max>`, `enum:<a>|<b>|<c>`, `bool`, `path:<maxlen>`, `netname`.

Types specific to these authenticated documents:

| Type | Accepts | Notes |
|---|---|---|
| `docver` | a non-negative decimal integer, bounded to 18 digits | The document's own version, used for anti-rollback. |
| `epoch` | a non-negative decimal integer, bounded to 18 digits | Unix seconds. Compared against the host clock — see the residual on clock dependence below. |
| `ident` | `[a-z][a-z0-9-]{0,63}` | A product or role identifier. |
| `sha256` | exactly 64 lowercase hex characters | A raw digest, compared as a literal string — an uppercase-but-otherwise-correct digest does not match. |
| `digestref` | `<repository>@sha256:<64 hex>` | An image reference **pinned by content digest**: the value must carry `@sha256:` followed by exactly 64 lowercase hex characters, and a bare tag with no digest (`:latest`, `:v1`) is refused — there is no floating reference this format can express, by construction, not by a denylist of tags an attacker would simply avoid. The `<repository>` half is shape- and charset-bounded but is **not** fully parsed — telling a tag apart from a registry-host port (`host:5000/repo`) needs Docker's full reference grammar, which this project deliberately does not implement. The bound it does carry, in full: at most 255 bytes; lowercase letters, digits and `. _ - / :` only (an uppercase byte is refused); it may not begin or end with `/` or `:`; and it may not contain `//`, `::`, `:/` or `/:`, each of which brackets an empty component and is not a valid reference. So a tag **may** appear alongside the digest (`repo:latest@sha256:<64 hex>`) and is simply ignored: the digest is what selects the image, so the value is still pinned to one exact content hash either way. |
| `productdigest` | `<product>:<64 hex>` | The family index's flat encoding of "this product's manifest must hash to this." Exactly one colon. |
| `coreversion` | `MAJOR[.MINOR[.PATCH]]`, numeric components only, each at most 18 digits | Deliberately not full semver — pre-release and build-metadata suffixes carry ordering machinery a minimum-core requirement has no need of. |
| `rolemount` | `<role>:/<absolute path>` | The flat encoding of what would be an object (`{role, mount}`) in a format that could nest. See [Residual: the format cannot nest](#residual-the-format-cannot-nest). No `..` component, and the path is at most 4096 bytes. **The path may contain no `:` of its own**: the first colon separates the role from the path, and a second one would make the split ambiguous in a format with no escaping — so a colon anywhere after it is refused, even though a colon is a legal byte in a pathname. |
| `cpath` | a bounded absolute container path of safe segments | A single mount point, stricter than `path:<maxlen>`: it must begin with `/`, each segment is `[A-Za-z0-9._-]+`, there is no trailing slash and the bare root `/` is refused, no empty (`//`) or `.`/`..` segment, no whitespace or control byte, and the length is 2..512 bytes. The tight charset is what makes the type **closed**: a value cannot carry a second token or an options list (a space, comma, colon, or `=` is refused), so a field of this type names *where* a mount lives and nothing about *how* it is mounted. See [The volatile credential-home mount](VOLATILE-MOUNT-FORMAT.md). |

Every type is checked byte by byte, with no collation or locale involved anywhere, so the same
document validates identically wherever it is read.

### What a `sha256` digest covers

This matters for every value typed `sha256` above — `policy_digest`, and the hex half of each
`manifest` entry — because a publisher computing one has to reproduce it exactly, and nothing in
this document tells you what bytes go in unless it says so explicitly, here:

**A digest is a plain SHA-256 over the entire raw file, byte for byte, exactly as it sits on disk.**
That means the header line, every comment line, every blank line, and the mandatory trailing
newline are all part of what gets hashed — nothing is stripped, trimmed, reordered, or normalized
before hashing. Compute it the plainest way there is: `sha256sum <file>` (or `shasum -a 256 <file>`
where that's what's available) over the file exactly as it will be shipped, and take the lowercase
hex digest.

**There is no canonicalization of any kind, and that is deliberate, not an oversight.** A publisher
who reasonably strips comments, sorts keys, or normalizes the trailing newline before hashing —
on the assumption that the digest covers "the meaningful content" — will produce a digest that
silently never matches the one the reader computes over the shipped file. Per
[Precedence](#precedence-the-order-these-checks-run-in) above, the only diagnosis you will ever see
for that mismatch is "does not match the digest the family index vouches for" — never a hint that
the difference was a stripped comment or a missing trailing newline. Canonicalizing before hashing
would mean writing a second parser whose entire job is to decide which bytes "count" — and a second
parser is a second thing to get wrong, on the one value this format uses to decide whether to trust
anything else in the document. Hash the file exactly as you ship it.

## The family index (`mythical-index 1`)

The **one trust root** (see [Trust model](#trust-model)). Every other document is verified against
something this index says, directly or transitively.

| Key | Type | Cardinality | Meaning |
|---|---|---|---|
| `version` | `docver` | one | This index's own version, for anti-rollback. |
| `expires` | `epoch` | one | Mandatory. An index with no expiry would let the highest version ever served replay forever against an installation that has been offline. |
| `policy_digest` | `sha256` | one | The digest the family policy index must hash to. |
| `manifest` | `productdigest` | many | One entry per product: `<product>:<64-hex digest>`. A product listed **twice** makes the index ambiguous about which digest vouches for it, and is rejected at load time, not merely at the moment someone looks that product up. |
| `probe_image` | `digestref` | one | The pinned image the health probe runs. |
| `copy_image` | `digestref` | one | The pinned image the volume copy runs — the helper `backup`, `restore` and `migrate-storage` hand a product's data to. |

**The two helper images belong here, and are required here.** They are images this tool runs
itself, and the copy helper in particular is handed every byte of a product's data with a
writable mount — so the reference that selects it has to arrive through the same chain as
everything else, named by the one document verified against the persisted anchor, rather than
being read out of local configuration or resolved to whatever small utility image happens to be
on the machine. `digestref` refuses a floating tag by construction. They are `one`, not `opt`:
an index that does not name them does not load at all, so there is no verified index from which
a helper reference can be missing at the moment one is needed.

## The family policy index (`mythical-policy 1`)

**Authenticity is not authorization.** A manifest signed by its real publisher can still ask for a
sibling's state volume or another product's bootstrap secret — verifying who wrote a manifest never
answers whether it may have what it asks for. So entitlements live in a **separate, authenticated**
document, deliberately not folded into the manifest and deliberately not hard-coded in the core
(which carries no product-specific logic).

This document has **two separate key namespaces**, and they are validated against **two separate
schemas** — never one union schema — because a single spec that accepted both kinds would let a
publisher's typo silently pass in either direction: a document-level key written with a product
prefix would validate as a meaningless per-product setting, and a per-product entitlement key
written *without* its prefix would validate while granting nothing to anyone. On the one document
whose entire job is authorization, a typo that grants nothing and reports nothing is the worst
possible failure.

**Document-level keys** (never product-prefixed):

| Key | Type | Cardinality | Meaning |
|---|---|---|---|
| `version` | `docver` | one | This policy's own version. |
| `expires` | `epoch` | one | Mandatory, for the same reason as the index's. |
| `family_gid` | `int:1:4294967295` | one | **The canonical family group id.** Required — see [The family gid](#the-family-gid-family_gid) below. |

**Entitlement keys** (always product-prefixed, e.g. `brokkr.permitted_role`):

| Key | Type | Cardinality | Meaning |
|---|---|---|---|
| `<product>.permitted_role` | `ident` | many | A volume role this product may declare in its manifest. |
| `<product>.bindable_role` | `ident` | many | A subset of the above: a role the **operator** may additionally point at a host directory of their own, rather than leaving it on a named volume. The bind path is named in `mythical.conf`, which is host-only — the product's own settings UI never writes it and cannot ask for a bind. This key grants the operator that option; it grants the product nothing. |
| `<product>.precious_role` | `ident` | many | A subset of `permitted_role`: a role whose volume holds data that **cannot be regenerated**. A data class, not a permission — it grants nothing and denies nothing. See [Precious roles](#precious-roles-precious_role) below. |
| `<product>.permitted_secret` | `str:128` | many | A bootstrap secret name this product may request. |
| `<product>.permitted_mount` | `ident` | many | A fixed mount this product may declare. |

**The structural invariant: `bindable ⊆ permitted`, always, and a policy that violates it is
rejected as malformed, not silently repaired.** A policy index that lists a role as bindable without
also listing it as permitted is nonsensical on its face — bindable is a *tightening* of permitted,
never a way to grant a role that was never permitted in the first place — and is refused wholesale,
naming the offending product and role.

**A role named `secrets` can never be bindable, for any product, and a policy declaring it so is
rejected the same way.** `secrets` is reserved as *the* role whose entire purpose is to be permitted
but never bindable: it is exactly the entitlement that must always come from a named, installer-
managed volume, never from an operator-chosen bind path, because that is the one role a bind would
turn into a one-line way to relocate a credential store outside the installer's control. This is not
softened by any per-product override — the reservation is structural, checked at policy-load time,
regardless of what any single product's own entries say.

### Precious roles (`precious_role`)

A role listed here holds data that **cannot be rebuilt**. Every other key in this document decides
what a product may *have*; this one decides nothing at all about permission, and is deliberately not
a tightening of anything. It exists because there was no vocabulary for the distinction: every named
volume was removed identically by `uninstall --purge`, and the host-path classification elsewhere in
this tool has no volume concept at all. So the one operation that destroys unrecoverable data could
not say which of the things it was about to destroy were unrecoverable — and neither could `status`.

**Why it lives here rather than in the manifest.** For the same reason every entitlement does: this
tool carries no product-specific logic, and a product's own self-description must not be the
authority on how carefully its data is treated. A manifest that under-declared would buy itself a
quieter purge. *Authenticity is not authorization* applies to a product describing its own data as
readily as to one requesting a sibling's volume.

**`precious ⊆ permitted`, and a policy that violates it is rejected as malformed**, exactly like
`bindable`. A declaration naming a role that is not permitted classifies a volume this installation
will never create, so it takes effect nowhere and reports nothing — and here the specific cost of
that silence is an operator who believes their unrecoverable data is flagged when the purge path will
never see the flag.

**`precious` and `bindable` compose freely, on purpose.** There is no rule against a role being both.
Unrecoverable data is exactly the data an operator most legitimately wants to relocate onto a larger
or backed-up disk, so making the two exclusive would penalise the safest thing they could do with it.

**What consumes it.** The class is resolved at volume-creation time and recorded on the volume's own
ledger record, rather than re-derived when something is about to be deleted. A product being
uninstalled may be one whose manifest has been withdrawn, so a purge that needed the documents to
answer "is this recoverable?" would either fail closed and be unable to uninstall anything, or fall
back to a default — and the only available default answers in the direction that costs data. Reading
it from the checksummed ledger removes the choice.

**An absent classification reads as unrecoverable, never as safe.** A record written before this key
existed makes no claim, and no claim means this tool does not know. `status` reports such a volume as
`UNREGENERABLE (unclassified)` and `--purge` lists it under the unrecoverable heading. Only an
explicit classification of *regenerable* is treated as a statement that the contents can be rebuilt.

### The family gid (`family_gid`)

An earlier design fixed a family group id — the Unix group every product container runs as, so that
sibling products can share state through the filesystem without running as each other — as a
hard-coded default inside this project's own configuration code. That shape was wrong: as long as
the default lived in code, it was a **second authority** for the value, competing with whatever an
operator's actual policy index said, and on any installation made before the two were unified, the
hard-coded default silently won. There is now exactly one authority for this value: the family
policy index, via `family_gid`. Nothing in this project's configuration layer can answer "what is
the family gid" on its own, and no default is coming — that absence is deliberate and is not a gap
to fill in later.

**Recommended value and range, for a publisher choosing one:** `60748`. The reasoning for the range,
not just the number: it must sit **above** the ordinary user/group id range `useradd` allocates by
default (`GID_MAX` in `/etc/login.defs`, conventionally `60000`) so it never collides with an
ordinarily-created system or user group, and it must sit **below** the range systemd reserves for
its own `DynamicUser=` transient service users (conventionally starting at `61184`), so it never
collides with an id systemd itself might hand out dynamically on the same host. `60748` sits inside
that gap. A publisher is free to choose a different value that satisfies the same two bounds; the
bounds are the part of this that is load-bearing, not the specific integer.

## The manifest (`mythical-manifest 1`)

Declares one product's install-time shape: what image runs, what it mounts, what it needs. **A
manifest declares roles; it never names resources.** It says "I have a state volume", never
"`mythical-brokkr-state`" — the concrete container, volume, and network names are derived by the
core from the installation identity plus the product identity, and a manifest has no vocabulary in
which to reach outside its own product's names. This is why several keys a nested format might
expect are simply absent from the grammar below; their absence is the enforcement, not an oversight.

| Key | Type | Cardinality | Meaning |
|---|---|---|---|
| `version` | `docver` | one | This manifest's own version. |
| `expires` | `epoch` | one | Mandatory, for the same reason as the index's. |
| `product` | `ident` | one | The product this manifest is for. Checked against the product the installer asked for — a perfectly valid manifest for a sibling product is still the wrong answer. |
| `launched` | `bool` | one | **Declared, never inferred.** Whether this product has a published image yet. Required: inferring "not launched" from, say, a registry 404 would turn a broken publication into a reassuring "not launched yet" notice instead of an error. |
| `image` | `digestref` | one | The image to run, pinned by content digest. |
| `volume` | `rolemount` | many | `<role>:<mount point>` — see the `rolemount` type above. A role may be placed **at most once**: the same role at two mount points is two answers to a question that has one, and the launch refuses rather than letting record order decide which directory appears where. |
| `secret` | `str:128` | many | A bootstrap secret name this product needs injected. Three things must hold when the launch is assembled, or it refuses: the policy index grants this product that name; the name is a key `mythical.conf`'s **core vocabulary defines** — a product selects from that vocabulary and cannot name an arbitrary key; and the key is actually **set** there — a declared secret with no value is a refusal, never an empty injection. |
| `mount` | `ident` | many | A fixed mount this product needs. **The selectable vocabulary is closed to `transcripts` and `logs`** — the two core-fixed directory mounts. `conf` is not selectable, because `<product>.conf` is mounted for every product whether or not the manifest asks. Any other name is refused when the launch is assembled, even though the `ident` type accepts it and the policy index can be written to grant it. |
| `port` | `int:1:65535` | many | A port this product's container listens on. |
| `probe` | `str:256` | opt | An optional health-check path. **Declared and validated, but consumed by nothing in this release** — no verb reads it, so supplying it changes no behaviour today. It is listed because the schema accepts it and a manifest carrying it loads; it is not listed as something that does anything. |
| `volatile_mount` | `cpath` | opt | Where this product's credential-bearing isolated-home mount lives, for a product that materializes a file-based credential per session. A bare mount point and nothing else: every hardening property of the mount is **fixed** and is not declared here, so a manifest names only the path and can never widen the mount. See [The volatile credential-home mount](VOLATILE-MOUNT-FORMAT.md). Optional — a product needing no such mount omits it. |
| `min_core` | `coreversion` | one | The minimum `mythical-ctl` version this manifest requires. Required — an unstated minimum would silently mean "any core will do," which is never a safe default for a document this privileged. |
| `runtime_uid` | `int:0:4294967295` | one | The uid this product's container runs as. Required, because migration **maps** ownership rather than preserving it, and this is the principal it maps to. Guessing it, or preserving uid/gid raw, is the dual-owner problem at directory scale: a preserved `0600` file owned by the operator is unreadable by a container still running as uid 900 — and a wrong value here does not fail loudly, it produces a migrated tree the product cannot read, discovered on the first start after the source has already been retired. |

### Keys that do not exist, and why

These are not omissions to be added later. Each is deliberately absent, and each falls out of the
manifest's allowlist as an **unknown key** if a product ships one — which is louder than silently
ignoring it: a product author who tries one of these learns immediately, from a rejection naming the
key, rather than shipping a field that quietly does nothing.

- **`bindable_role`.** Bindability is an *entitlement*, decided by the family policy index
  (`<product>.bindable_role`), never claimed by the product itself. A manifest that could declare
  its own roles bindable could grant itself a capability no publisher ever authorized.
- **`precious_role`.** The same rule, applied to something that is not a permission at all. Whether a
  role's data can be regenerated is decided by the policy index (`<product>.precious_role`), because a
  manifest that classified its own data could **under**-declare and buy itself a quieter `--purge` —
  the one direction where a product's self-description costs the operator something irreversible. A
  product may say which roles it needs; it does not get to say how carefully they are treated.
- **`network`.** A manifest cannot ask to join a network. Cross-product network reach is exactly the
  boundary the authenticated policy/entitlement model exists to hold — a product declaring which
  network it joins is a product declaring who it can talk to, and that is not this document's
  decision to make.
- **`volume_name`.** A manifest selects a **role** (`volume=state:/data`); it never names the
  resulting volume. Names are derived by the core from the installation identity and the product
  identity. A manifest with a `volume_name` key could, in principle, spell out another installation's
  or another product's actual resource name and collide with or adopt it; a manifest that can only
  speak in roles cannot reach outside its own product's namespace to do so.

## Trust model

The family index is the **only** root. Nothing else authenticates itself: a digest is not
authentication on its own — verifying a document against a digest that merely arrived beside it
proves only that whoever sent both computed one correctly. A digest is meaningful *only* when the
expected value came from a document that was itself already authenticated. So the family index is
verified against a locally recorded **anchor** — a digest held in this installation's own state
(see [the residual on the anchor](#residuals) below); the
family policy index and every product's manifest are then verified against digests **the index
itself names** (`policy_digest`, and one entry per product under `manifest`); nothing is ever
accepted on its own say-so. Every document additionally carries a **version**, which can only move
forward for a given document identity once accepted — an older version is refused as a replay, even
if it is byte-for-byte a document that was once valid — and an **expiry**, which is mandatory on
every document type here (unlike `<product>.conf`, which has none): without one, the single highest
version anyone ever legitimately served would remain replayable forever against a machine that has
been offline. A version floor, once recorded, only moves down through an explicit, reasoned,
recorded downgrade — never through the ordinary acceptance path — because an emergency rollback that
could happen silently would not be an emergency rollback, it would be exactly the replay this model
exists to prevent. The ordinary path only ever raises the floor, and it refuses to lower it; no verb
in this release performs a downgrade.

Every digest in this chain — the anchor, `policy_digest`, each `manifest` entry — is computed the
same way: a plain SHA-256 over a document's entire raw bytes, header line and trailing newline
included, with no canonicalization (see [What a `sha256` digest covers](#what-a-sha256-digest-covers)
above). This is why digest verification is the *first* check run against any of these documents, not
merely *a* check among several (see [Precedence](#precedence-the-order-these-checks-run-in)): a
digest computed over exact, unmodified bytes is only meaningful if it is checked before those bytes
have been touched by anything — a byte-policy pass, a parser, a canonicalizer — that might read,
normalize, or reject them on the way.

## `/detect`: JSON read without being decoded

`/detect` is a live HTTP endpoint each running product exposes, and its response body is JSON — that
is defined by the products themselves, not by this document, and it is not this project's format to
change.

**No verb in this release reads `/detect`.** The reader described in this section exists in the
source, but nothing in the command set calls it — it is not even in the shipped binary's dependency
graph — so what a product puts in that response changes nothing about this release's behaviour. The
section stays because these rules are the contract a product's response has to satisfy, and because
they are why the reader is shaped the way it is — not because a command runs them today.

The reader needs exactly three flat string fields out of that response — `product`, `version`,
`ui_url` — and it does not hand the body to a JSON decoder to get them. That is a
choice, not a missing capability: a decoding tokenizer makes a literal `"product"` and an escaped
spelling of it indistinguishable, and this reader has to **refuse** the escaped spelling rather
than match it. So it reads those three fields with a small bounded scanner that works on raw bytes
and understands JSON's *shape* well enough to find top-level members and tell a plain string apart
from everything else, and it **refuses** — rather than guesses at — anything it cannot read
unambiguously:

- **The whole response is capped at 32768 bytes (32 KiB)**, checked before a single byte reaches
  the scanner, and a response over the cap is refused outright, naming both the cap and the size
  that exceeded it. The scan itself is a single linear pass, so the cap is not bounding an
  algorithm — it is there because the input is a live reply from a product's own container, which
  makes its size something that product controls. No real `/detect` response comes close to the
  cap.

- A value containing any escape sequence (`\"`, `\\`, `\n`, `\uXXXX`, …) is refused, not decoded. A
  product that starts escaping characters in `product`, `version`, or `ui_url` will see its response
  reported as unreadable; the fix is on the product side, not a reason to add a decoder here.
- A value that is a number, `true`, `false`, `null`, or a nested object or array is refused — these
  three fields are defined as flat strings, and anything else is not one.
- A field repeated at the top level is refused as ambiguous, rather than resolved by "first wins" or
  "last wins."
- A field that exists only *inside* a nested object (`{"components":{"version":"…"}}`) is never
  mistaken for the top-level field of the same name — the scanner tracks brace/bracket depth
  precisely so this cannot happen, since this is the one way a naive pattern match could make the
  reader return a **wrong** answer instead of no answer at all.
- Malformed document structure is refused — but **how deep that check reaches differs by kind, and
  the difference is deliberate**, so it is worth stating exactly rather than claiming more than is
  enforced:

  | malformed structure | at the top level | inside a nested object or array |
  |---|---|---|
  | unmatched or mismatched delimiters | refused | **refused** |
  | an invalid escape (`"\q"`, `"\u12"`) | refused | **refused** |
  | an invalid bare literal (`tru`, `01`, `1e`) | refused | accepted |
  | bad member sequencing (a missing comma) | refused | accepted |
  | a repeated key — the field being queried | refused | accepted |
  | a repeated key — any other top-level key | accepted | accepted |

  Delimiters and escapes are checked at **every** depth because the scanner has to track both in
  order to know where a value ends — get either wrong and it could lose its place and report a
  *nested* field as a top-level one, which is the single way this reader could return a wrong answer
  instead of no answer. The other three are **not** checked inside a nested value, because doing so
  would mean interpreting content this reader has no reason to interpret: it needs three top-level
  flat strings, and a semantic error inside `components` neither affects them nor is any of its
  business. This reader validates enough to guarantee *its own answer*; it is not, and does not
  claim to be, a JSON validator. A response whose top level is well formed is answered from, even
  if something deeper inside it is not valid JSON.

  **The repeated-key row splits in two because "refused" there means something narrower than for the
  other rows: only a repeat of the field being queried is refused.** The reader checks whether
  *its own answer* is ambiguous, not whether the response contains a duplicate key anywhere. Querying
  `version` in `{"x":"a","x":"b","version":"1"}` succeeds and returns `1`; querying `x` in that same
  response is refused as ambiguous. A duplicate of some other top-level key is never inspected,
  because it does not affect the field being asked about — consistent with the same "guarantees its
  own answer, not a JSON validator" limit stated above.

**One asymmetry worth stating plainly: an escaped *key* is reported as absent, not unreadable.** A
response containing the key `"pro\u0064uct"` (which, decoded, spells
`product`) is treated as not having a `product` field at all, because escapes are never decoded
anywhere in this reader — including in keys — so it has no way to know that key was meant to be
`product`. This is a narrower guarantee
than "every way of spelling this key is recognized"; it is stated here because it is the one case
where the honest answer ("this reader cannot tell") and the intuitive one ("that key was clearly
meant as `product`") diverge, and the honest one is what ships.

`version` is the field this reader prefers. `image_version` is a **deprecated alias**, consulted
in exactly two of the three ways `version` can come back: when `version` is **absent**, and when it
is present and **empty**. It is never consulted when `version` is present but **unreadable** —
something was reported and this reader failed to read it, and answering from a different field
would hide that; that case reports the explicit `unknown` marker instead, as does a response in
which neither field yields a usable value. The reader never fabricates a value, and never inherits
one from a sibling field such as `components.ui`'s version — unmeasured is not measured-clean, the
same principle this format applies to unattested products in the family index.

## Residuals

**Residual: the format cannot nest.** Every structure one of these documents needs — a role and its
mount point, a product and its digest — is a flat pair, encoded as one delimited value
(`role:/mount/point`, `product:digesthex`) rather than as a nested structure, because this format
has none. That costs nothing today: nothing here needs more than one level of pairing. It is not a
feature to lean on further — a future document that genuinely needs real nesting is a deliberate
**floor decision** (choosing to add a parsing dependency on purpose), not something to back into by
stacking more delimiters into one value.

**Residual: expiry depends on the host clock.** A machine with a badly wrong clock will either
refuse currently-valid documents or accept ones that should have expired. There is no environment
override for the "current time" this is checked against in normal operation — an override that could
make an expired document look current would defeat the exact replay protection expiry exists to
provide.

**Residual: nothing in this release establishes the anchor.** Every verification of a family index
is checked against a digest already recorded in this installation's own state, and an installation
with no such record **refuses** to verify an index rather than adopting whatever it was handed. What
this release does not have is a path that *derives* a first one from an index it verified. Three
things touch the record, and none of them is that: `state repair` preserves an existing anchor
across a ledger rebuild; `uninstall --family` clears it; and `restore`, which stages and activates
a ledger captured by `backup`, transplants onto a machine with no installation whatever anchor the
backed-up installation already held. This release also fetches nothing — the family index, the
policy index and the manifests are read as local files, named on the command line or found at
their default paths.

So the question a trust-on-first-use model has to answer — what vouches for the very first index,
before any anchor exists? — is not answered here, because nothing here asks it. That is a gap in
what ships, stated rather than papered over. It changes nothing about this format or about a
publisher's obligations: a document that will be verified against an anchor is produced exactly the
same way as one that would establish it.
