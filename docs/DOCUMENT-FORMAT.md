# The authenticated document format

`mythical-ctl` accepts three kinds of document from outside the machine it runs on: a **family
index**, a **family policy index**, and a per-product **manifest**. This document is the contract
those three follow. It is written for the people who produce them and never read this repository's
source to do it: a **product author** writing a manifest, and a **family/policy publisher** signing
the family index and the policy index. It is normative — a document that does not follow it is
rejected, and rejection is not a bug.

These documents are **more privileged than `<product>.conf`**, not less. A manifest names the image
that will run, the mounts that will be made, and the secrets that will be injected. Every rule
[`docs/CONFIG-FORMAT.md`](CONFIG-FORMAT.md) places on product configuration binds here too, plus the
authentication and freshness rules this document adds on top.

## Why line-oriented `key=value`, not JSON

Every document in this family — including the family index and the policy index — is the same
`key=value` text format `<product>.conf` uses, not JSON. `/detect` is the one place in the system
that speaks JSON, and it does so because it isn't ours: it's an existing HTTP response from a
product's own runtime, defined separately (see the note on `/detect` at the end of this document).
Everything *authenticated* — the index, the policy, the manifest — is emitted and consumed
entirely inside this project's own tooling, so there is no external format to inter-operate with,
and the dependency floor (bash, a container runtime, `curl`, `mktemp`, `sha256sum`/`shasum` — no
`jq`, no JSON parser) rules JSON out anyway: hand-rolling a JSON parser in bash to read the most
security-sensitive input in the system would be the least reviewable code in the repository.

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

The body — everything after the header line — is line-oriented text, and it is never `source`d,
`eval`d, or shell-expanded by anything that reads it:

- Every line ends with `\n`, **including the last**. A file that doesn't end in a newline is
  rejected as truncated.
- Blank lines and lines starting with `#` are ignored.
- Every other line is `KEY=VALUE`, split on the **first** `=`. A value may itself contain `=`.
- A key is lowercase ASCII, and may carry **exactly one** dotted prefix: `brokkr.permitted_role` is
  legal, `a.b.c` is not. The prefix, when present, must itself be a valid product identifier (see
  `ident` below). This is how the policy index scopes an entitlement to one product without the
  format needing real nesting — see [Residual: the format cannot nest](#residual-the-format-cannot-nest).
  A key that is not in the document's schema is **rejected, not ignored** — the whole document fails
  to load, the same as an unknown key in `<product>.conf`.
- A duplicate key is rejected, unless the document's schema explicitly marks that key repeatable
  (`many`, below) — in which case every occurrence is kept, in order.
- At most 1024 keys per document. This is the same ceiling `<product>.conf` and `mythical.conf`
  carry, and for the same reason: the cost of detecting a violation is incurred *while accumulating*
  the document, so a generous, cheap-to-check ceiling exists rather than an after-the-fact one.

### Byte and value rules (inherited from `docs/CONFIG-FORMAT.md`)

The byte policy and the value rule are **exactly** `docs/CONFIG-FORMAT.md`'s — the same check, not a
second implementation of it:

- **No control bytes** anywhere except the `\n` that ends each line (no NUL, CR, TAB, DEL). A file
  containing one is rejected outright, before the marker or the schema is even considered.
- **Values**: no leading or trailing space; no control characters; none of `$`, `` ` ``, `\`; bounded
  length. Any other byte is passed through verbatim, including non-ASCII (UTF-8) content — the
  reader never decodes a value, so it never needs to validate UTF-8.
- **No quoting and no escaping.** A value is the literal bytes between the first `=` and the end of
  the line. Do not wrap a value in quotes; the quotes become part of it.

If you are implementing a writer for one of these documents, read `docs/CONFIG-FORMAT.md`'s
"Syntax" and "Writing safely" sections in full — they describe the same rules in more depth, with
worked examples, and apply here without change.

## Precedence: the order these checks run in

An implementer's first instinct is usually to check the checks in the order that's easiest to
write, which is not the order this format is actually verified in. The order matters because each
step's failure mode is a different, specific answer, and collapsing two into one gives an operator
the wrong diagnosis. In the order they actually run, for every document handled through this
project's acceptance path (`mi_accept_index`, `mi_accept_policy`, `mi_accept_manifest`):

1. **Does the document authenticate against its digest?** This runs **first**, over the file's raw
   bytes — before the byte policy, the grammar, or the schema are applied to those bytes at all.
   (The file must of course be openable to be hashed in the first place; that is a mechanical
   precondition for computing anything, not a content check with its own diagnosis — the byte policy
   below is what inspects what the bytes actually *contain*, and that is what step 2 gates on.) The
   expected digest for an index comes from the trust anchor (see [Trust model](#trust-model)); the
   expected digest for a policy index or a manifest comes from the *already-authenticated* parent
   document (the family index) that names it. A digest that does not match is rejected immediately,
   and the bytes are **never inspected further** — only a verified copy is handed to anything that
   reads content, never the live pathname a second time. Verifying the digest before looking at the
   content is the whole point: nothing may be judged on what it says until something
   already-authenticated has vouched for its bytes.
2. **Only once the digest matches** are the bytes handed to anything that looks at their content —
   and the byte policy (readable at all; no control bytes; ends in a newline) is the *first* thing
   that content-reading step does, immediately followed by the header line, the grammar above, and
   the document's own schema (which fields exist, their types, their cardinality). A control byte, a
   missing trailing newline, or a malformed line is rejected here — but only ever for a document that
   has already authenticated.
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
| `digestref` | `<repository>@sha256:<64 hex>` | An image reference **pinned by content digest**. A tag (`:latest`, `:v1`) is not a digest and is never accepted here — there is no floating reference this format can express, by construction, not by a denylist of tags an attacker would simply avoid. |
| `productdigest` | `<product>:<64 hex>` | The family index's flat encoding of "this product's manifest must hash to this." Exactly one colon. |
| `coreversion` | `MAJOR[.MINOR[.PATCH]]`, numeric components only | Deliberately not full semver — pre-release and build-metadata suffixes have ordering rules a shell comparator would get subtly wrong, and a minimum-core requirement has no need of them. |
| `rolemount` | `<role>:/<absolute path>` | The flat encoding of what would be an object (`{role, mount}`) in a format that could nest. See [Residual: the format cannot nest](#residual-the-format-cannot-nest). No `..` component. |

Every type is checked in byte order (`LC_ALL=C`), so the same document validates identically
whatever locale the reader runs under.

### What a `sha256` digest covers

This matters for every value typed `sha256` above — `policy_digest`, and the hex half of each
`manifest` entry — because a publisher computing one has to reproduce it exactly, and nothing in
this document tells you what bytes go in unless it says so explicitly, here:

**A digest is a plain SHA-256 over the entire raw file, byte for byte, exactly as it sits on disk.**
That means the header line, every comment line, every blank line, and the mandatory trailing
newline are all part of what gets hashed — nothing is stripped, trimmed, reordered, or normalized
before hashing. Compute it the same way the reference tooling does: `sha256sum <file>` (or
`shasum -a 256 <file>` where that's what's available) over the file exactly as it will be shipped,
and take the lowercase hex digest.

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
| `<product>.bindable_role` | `ident` | many | A subset of the above: a role this product's own settings UI may additionally point at an operator-chosen bind path, rather than only a named volume. |
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
| `volume` | `rolemount` | many | `<role>:<mount point>` — see the `rolemount` type above. |
| `secret` | `str:128` | many | A bootstrap secret name this product needs injected. |
| `mount` | `ident` | many | A fixed mount this product needs. |
| `port` | `int:1:65535` | many | A port this product's container listens on. |
| `probe` | `str:256` | opt | An optional health-check path. |
| `min_core` | `coreversion` | one | The minimum `mythical-ctl` version this manifest requires. Required — an unstated minimum would silently mean "any core will do," which is never a safe default for a document this privileged. |

### Keys that do not exist, and why

These are not omissions to be added later. Each is deliberately absent, and each falls out of the
manifest's allowlist as an **unknown key** if a product ships one — which is louder than silently
ignoring it: a product author who tries one of these learns immediately, from a rejection naming the
key, rather than shipping a field that quietly does nothing.

- **`bindable_role`.** Bindability is an *entitlement*, decided by the family policy index
  (`<product>.bindable_role`), never claimed by the product itself. A manifest that could declare
  its own roles bindable could grant itself a capability no publisher ever authorized.
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
verified against a locally recorded **anchor** (a digest, established the first time this
installation successfully verified an index — see the residual on trust-on-first-use, below); the
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
exists to prevent.

Every digest in this chain — the anchor, `policy_digest`, each `manifest` entry — is computed the
same way: a plain SHA-256 over a document's entire raw bytes, header line and trailing newline
included, with no canonicalization (see [What a `sha256` digest covers](#what-a-sha256-digest-covers)
above). This is why digest verification is the *first* check run against any of these documents, not
merely *a* check among several (see [Precedence](#precedence-the-order-these-checks-run-in)): a
digest computed over exact, unmodified bytes is only meaningful if it is checked before those bytes
have been touched by anything — a byte-policy pass, a parser, a canonicalizer — that might read,
normalize, or reject them on the way.

## `/detect`: the one place this project reads JSON, and does not parse it

`/detect` is a live HTTP endpoint each running product exposes, and its response body is JSON — that
is defined by the products themselves, not by this document, and it is not this project's format to
change. `mythical-ctl` needs exactly three flat string fields out of that response — `product`,
`version`, `ui_url` — and, per the dependency floor above, has no JSON parser and will not grow one.
So it reads those three fields with a small bounded scanner that understands JSON's *shape* well
enough to find top-level members and tell a plain string apart from everything else, and it
**refuses** — rather than guesses at — anything it cannot read unambiguously:

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
- Malformed document structure — unmatched or mismatched delimiters, bad member sequencing (a
  missing comma), an invalid bare literal, an invalid escape — is refused wholesale, the same as a
  malformed value. A response is not partially trusted.

**One asymmetry worth stating plainly: an escaped *key* is reported as absent, not unreadable.** A
response containing `"product"` (which, decoded, spells `product`) is treated as not having a
`product` field at all, because escapes are never decoded anywhere in this reader — including in
keys — so it has no way to know that key was meant to be `product`. This is a narrower guarantee
than "every way of spelling this key is recognized"; it is stated here because it is the one case
where the honest answer ("this reader cannot tell") and the intuitive one ("that key was clearly
meant as `product`") diverge, and the honest one is what ships.

`version` is the field `mythical-ctl` prefers. `image_version` is a **deprecated alias**, read only
when `version` is entirely absent (never when `version` is present but unreadable — an unreadable
`version` must not be silently answered from a different field). A response carrying neither reports
an explicit `unknown` marker. It never fabricates a value, and it never inherits one from a sibling
field such as `components.ui`'s version — unmeasured is not measured-clean, the same principle this
format applies to unattested products in the family index.

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

**Residual: the anchor is trust-on-first-use.** The first successful verification of a family index
establishes the anchor that every later verification is checked against; nothing authenticates that
very first fetch beyond TLS to a known origin. This is a stated limit of the model, not an
oversight, and this document does not claim otherwise.
