package copyfill

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/probe"
)

// lines splits a helper transcript into records the way the reference's `$(…)` capture did:
// TRAILING newlines are stripped, interior ones are not.
//
// THAT ASYMMETRY IS LOAD-BEARING, not an accident of shells. A conforming transcript ends in
// exactly one newline, so a clean answer yields NO empty record — which is what lets an
// INTERIOR blank line be treated as evidence (grammarOK refuses it: it can be the truncated
// continuation of a value that contained a newline, at which point the record boundaries are
// no longer trustworthy). Splitting the raw bytes on "\n" instead would put a spurious empty
// record at the end of every clean answer and either refuse every copy or force the blank-line
// rule to be relaxed into uselessness.
func lines(out []byte) []string {
	s := strings.TrimRight(string(out), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// field is THE VALUE OF ONE STATED OBSERVATION. It is the probe's reader, not a second copy of
// it: the two pinned helpers share one response format, and a second implementation would be a
// second (drifting) opinion about what a REPEATED key means — an answer that says a thing
// twice says two things, and it is refused as ambiguous rather than read down to whichever
// copy came first. See probe.Field.
func field(out []byte, key string) (val string, found bool, err error) {
	return probe.Field(out, key)
}

// values returns EVERY value for a REPEATED key, in order. The repeated keys are the copy's own
// vocabulary — entry, linktarget, stripped, mapped, refused, mismatch — where a second copy of
// the key is a second OBSERVATION rather than a contradiction, which is why they are read here
// and not through the single-value reader above.
func values(out []byte, key string) []string {
	var vs []string
	for _, l := range lines(out) {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			vs = append(vs, v)
		}
	}
	return vs
}

// hasKey: is <key> STATED AT ALL, whatever its value — including an empty one? A problem record
// (`refused=`, `mismatch=`) is a problem by its PRESENCE, so it must be detected by the key, not
// by iterating its values: a value-iterating loop that skips empties then skips exactly the
// problem it was meant to catch.
func hasKey(out []byte, key string) bool {
	for _, l := range lines(out) {
		if strings.HasPrefix(l, key+"=") {
			return true
		}
	}
	return false
}

// hasEmpty: does the transcript carry a `<key>=` line whose value is EMPTY? Distinct from
// hasKey because an empty-valued record is the specific malformed shape a value-iterating loop
// drops — so it is detected on the raw lines, by the key followed immediately by end-of-line.
func hasEmpty(out []byte, key string) bool {
	for _, l := range lines(out) {
		if l == key+"=" {
			return true
		}
	}
	return false
}

// grammarOK: THE TRANSCRIPT IS A CLOSED GRAMMAR — every non-empty line must be
// `<allowed-key>=<value>` for a key this mode expects. A line that matches nothing is not
// harmless: it could be an unparsed CONTINUATION of newline-bearing data, at which point the
// whole `key=value` record grammar is no longer reliable and none of the per-key checks can be
// trusted. So a line outside the vocabulary FAILS CLOSED, naming the offending line.
//
// A WHOLLY-EMPTY transcript is not this function's to refuse: that is the "the helper reported
// nothing" case, which the absent-observation reader (stated) already refuses with a message
// that tells the operator WHICH observation was missing. Deferring it here keeps that
// diagnostic. A blank line only matters as an INTERIOR one, amid real content — that is the
// truncated-continuation shape.
func grammarOK(out []byte, allowed ...string) error {
	ls := lines(out)
	content := false
	for _, l := range ls {
		if l != "" {
			content = true
			break
		}
	}
	if !content {
		return nil
	}
	for _, l := range ls {
		if l == "" {
			return errors.New("copy: the helper's transcript contains a blank line. A blank line can be the truncated continuation of a value, so the record grammar is no longer reliable — refused")
		}
		key, _, ok := strings.Cut(l, "=")
		if !ok {
			return fmt.Errorf("copy: the helper emitted a line that is not a key=value record: %q. The transcript must be a closed grammar — an unrecognised line is refused, not ignored", l)
		}
		known := false
		for _, k := range allowed {
			if key == k {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("copy: the helper emitted a line with an unexpected key: %q. Only the keys this command defines are accepted; an unrecognised one is refused rather than ignored", l)
		}
	}
	return nil
}

// stated is THE ONE PLACE "ABSENT IS NOT OK" LIVES — the rule this whole module keeps getting
// wrong. A helper that ran, exited 0 and printed nothing would otherwise satisfy every contract
// check on no evidence at all: the destination declared able to hold ownership, permissions,
// symlinks and inherited ACLs because nobody said it could not. Unmeasured is not
// measured-clean. It is enforced HERE rather than at each of the eight call sites, because a
// rule every caller must remember is a rule that gets forgotten once, and the copy that is
// forgotten is the door nobody thought about.
//
// An EMPTY value is a real answer and is handed back as one. <noun> only names the observation
// in the refusal, so an operator is told what was missing rather than which key spells it.
func stated(out []byte, key, what, noun string) (string, error) {
	if noun == "" {
		noun = "the '" + key + "' observation"
	}
	v, found, err := field(out, key)
	if err != nil {
		// The shared reader's own refusal — the field is stated more than once — and it has
		// already said so. Restating it as "not stated at all" would report the wrong fact
		// about the answer.
		return "", fmt.Errorf("copy: reading the %s helper's answer: %w", what, err)
	}
	if !found {
		return "", fmt.Errorf("copy: the %s helper stated nothing about %s.\n  Refusing: a missing observation is not a passing one — unmeasured is not measured-clean", what, noun)
	}
	return v, nil
}

// entryPathOK: is <path> a CANONICAL absolute path under /src — the only shape a source entry
// may name? A source entry's identity is its canonical path, so `/src/a`, `/src/./a` and
// `/src/x/../a` are the SAME entry and must not be countable as three: a copier could otherwise
// pad the entry count (which binds verification) with spellings of one file while omitting a
// dangerous one. Purely lexical — the walk is by `/`-separated component, and any `.`, `..`,
// empty (`//`) or non-`/src` component is refused. A trailing slash is refused too (it is not
// how the copier names a leaf).
func entryPathOK(p string) bool {
	if p != "/src" && !strings.HasPrefix(p, "/src/") {
		return false
	}
	if strings.HasSuffix(p, "/") {
		return false
	}
	rest := strings.TrimPrefix(p, "/") // drop the leading slash; walk components
	for rest != "" {
		comp := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			comp, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		if comp == "" || comp == "." || comp == ".." {
			return false
		}
	}
	return true
}

// linktargetSplit UNAMBIGUOUSLY splits a `linktarget=` VALUE into the symlink's path and its
// verbatim target, regardless of colons in EITHER of them. The value is
// `<path><target>:<pathlen>` — a LENGTH-DELIMITED encoding whose trailing, colon-free field is
// the path's BYTE length: the path is the first <pathlen> bytes of the body and the target is
// the rest. This REPLACES a first-colon split, which reported the wrong path — and could MISS
// an escape — for a symlink whose own path contained a colon, a legal byte on every filesystem
// this runs on. The length is a fixed-shape (numeric) token placed where neither a path's nor a
// target's own bytes can reach it, the same discipline `refused=` (reason last) and `entry=`
// (type first) use for their one variable component.
//
// ok=false: the value is malformed (a non-numeric or out-of-range length). A linktarget the
// core cannot parse is REFUSED by the caller, never guessed: an unreadable target could be
// concealing an escape.
//
// Sliced in BYTES, never runes: <pathlen> is a byte length, and the reference pins the locale
// to C for exactly this slice.
func linktargetSplit(v string) (path, target string, ok bool) {
	pathlen, body := v, v
	if i := strings.LastIndex(v, ":"); i >= 0 {
		pathlen, body = v[i+1:], v[:i]
	}
	if pathlen == "" || !allDigits(pathlen) {
		return "", "", false
	}
	// A LEADING ZERO IS MALFORMED, and refusing it closes a silent wrong split rather than
	// porting one. <pathlen> is a fixed-shape token, so no conforming emitter ever pads it —
	// and the reference reads it in bash's ARITHMETIC context (`${body:0:pathlen}`), where a
	// leading zero means OCTAL. MEASURED against the frozen lib/copy.sh:
	//
	//	":08"  -> bash ERRORS ("value too great for base") and the split is refused, by accident
	//	          rather than by rule: its own digit test accepts "08" quite happily.
	//	":010" -> bash ACCEPTS and splits the body at 8, NOT 10.
	//
	// That second one is the dangerous shape: the path/target boundary lands in the wrong place,
	// so the bytes checked for an escape are not the bytes the copier disclosed as the target —
	// which is exactly how a target that escapes gets shown as one that does not. Reading the
	// token as decimal (as Go's parser does) would fix the boundary but diverge from the
	// reference's refusal of ":08"; refusing any padded length covers BOTH, costs nothing a
	// conforming copier will ever pay, and keeps the rule the module already states everywhere
	// else — a length this core cannot read unambiguously is refused, never guessed.
	if len(pathlen) > 1 && pathlen[0] == '0' {
		return "", "", false
	}
	// The path is at least one byte and cannot be as long as the body it prefixes. Bounded on
	// LENGTH before the arithmetic so an absurd stated length cannot overflow the conversion.
	// Strictly less, not at most: a path length EQUAL to the body would leave an EMPTY target —
	// a symlink pointing at nothing, which is not a real disclosed target and cannot be shown
	// not to escape. Refused, not read as clean.
	if len(pathlen) > 10 {
		return "", "", false
	}
	n, err := strconv.Atoi(pathlen)
	if err != nil || n < 1 || n >= len(body) {
		return "", "", false
	}
	return body[:n], body[n:], true
}

// linkEscapes: does a symlink at <linkpath> whose stored target is <target> point OUTSIDE the
// tree rooted at <root>? Purely LEXICAL — the target is never resolved on disk, because
// following it is exactly the escape this refuses (the host-side walk deliberately does not
// follow links either). A target escapes when it is ABSOLUTE, or when its `..` components climb
// above the root from the directory the symlink sits in. A verbatim intra-tree relative target
// (`../sibling/f`) is NOT an escape.
//
// A linkpath that is not under the root we were handed ESCAPES: the question cannot be answered
// about it, and a question that could not be asked is never an answer of "no".
func linkEscapes(linkpath, target, root string) bool {
	if strings.HasPrefix(target, "/") {
		return true // absolute → outside the tree by definition
	}
	if !strings.HasPrefix(linkpath, root+"/") {
		return true // not under the root we were handed — refuse, don't guess
	}
	rel := linkpath[len(root)+1:]
	// Depth of the symlink's PARENT directory below root = rel minus its last (basename)
	// component.
	dir := ""
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		dir = rel[:i]
	}
	depth := 0
	for rest := dir; rest != ""; {
		comp := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			comp, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		if comp == "" || comp == "." {
			continue
		}
		depth++
	}
	for rest := target; rest != ""; {
		comp := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			comp, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}
		switch comp {
		case "", ".":
		case "..":
			depth--
			if depth < 0 {
				return true
			}
		default:
			depth++
		}
	}
	return false
}

// LinkEscapes is the PUBLIC form of this module's escape rule. It is exercised from inside a
// single pass over the copier's transcript below; the migrate verb needs the SAME rule for a
// HOST-SIDE re-walk of an already-copied tree (re-verifying a staging directory immediately
// before it is committed into place), and a second, hand-written definition of "escapes" is
// exactly how the two drift apart. Exposed rather than duplicated.
func LinkEscapes(linkpath, target, root string) bool { return linkEscapes(linkpath, target, root) }

// The closed entry-type vocabulary. EVERY `entry=` is checked against it — not just `special`.
// A type outside the set is a `fifo:`/`socket:` a copier could otherwise smuggle past a
// `special`-only check: it would be counted toward a copy reported complete while nothing ever
// classified it.
var entryTypes = map[string]bool{"file": true, "dir": true, "symlink": true, "hardlink": true, "special": true}

// The closed refusal-reason vocabulary, read from the END of a `refused=` value. Every one of
// these has its own operator-facing message below: the reference distinguishes the cases
// deliberately, and a refusal an operator cannot act on is half a refusal.
var refusalReasons = []string{
	"special-entry", "escaped-write", "escaping-symlink", "staging-nonempty",
	"unknown-entry-type", "unreadable-linktarget", "missing-linktarget",
	"unassociated-linktarget", "duplicate-linktarget",
}

// refusals is EVERY REFUSAL THE ANSWER STATES, from every thing that can state one, in ONE
// place:
//
//	refused=<path>:<reason>                the copier's own refusal
//	entry=<type>:<path>                    EVERY enumerated entry, checked against the closed
//	                                       type set AND for its required companion record
//	linktarget=<path><target>:<pathlen>    a symlink it enumerated whose target ESCAPES <root>
//
// REQUIRED COMPANIONS ARE CROSS-CHECKED, not assumed. A `symlink` entry whose path has no
// matching `linktarget=` record is refused (missing-linktarget): its target was never
// disclosed, so the escape backstop never ran on it, and a copier could otherwise smuggle an
// escaping symlink past by omitting the linktarget (and any refused=) line while still counting
// the entry and reporting done=ok. That is the CLASS — an entry whose type carries required
// companion data must have it present. `file`/`dir` carry no core-required companion; a
// `hardlink`'s referent is a real in-tree inode, not an escapable target string, so it needs
// none.
//
// The last two are folded in HERE rather than checked beside the caller's loop because they are
// the same decision: an unclassifiable entry, or an escaping symlink, is a refusal whether or
// not the copier remembered to say so — a copier that enumerated one and then exited 0 must not
// be believed. Two separate checks would be two verdicts that can drift, and the one that
// drifts is the one nobody re-reads.
func refusals(out []byte, root string) []string {
	var res []string
	res = append(res, values(out, "refused")...)

	// THE SET OF `symlink` ENTRY PATHS, gathered FIRST, so a `linktarget=` can be required to
	// ASSOCIATE with exactly one symlink. One symlink has exactly one stored target, so the
	// relation is ONE-TO-ONE — and a transcript that violates it (a linktarget for a path that
	// is not a symlink entry, or two linktargets for one symlink) is a contradiction the core
	// can detect and must refuse, otherwise a copier can attach a benign target to a symlink
	// while also emitting an escaping one, or disclose a target for something it did not
	// enumerate.
	sympaths := map[string]bool{}
	for _, v := range values(out, "entry") {
		if v == "" {
			continue
		}
		if p, ok := strings.CutPrefix(v, "symlink:"); ok {
			sympaths[p] = true
		}
	}
	// LINKTARGETS: each must parse, ASSOCIATE with a symlink entry, occur EXACTLY ONCE for that
	// symlink, and not escape. ltpaths records the associated ones so the entry pass can
	// confirm every symlink disclosed a target.
	ltseen := map[string]bool{}
	ltpaths := map[string]bool{}
	for _, v := range values(out, "linktarget") {
		if v == "" {
			continue
		}
		p, target, ok := linktargetSplit(v)
		if !ok {
			res = append(res, v+":unreadable-linktarget")
			continue
		}
		if !sympaths[p] {
			res = append(res, p+":unassociated-linktarget")
			continue
		}
		if ltseen[p] {
			res = append(res, p+":duplicate-linktarget")
			continue
		}
		ltseen[p] = true
		ltpaths[p] = true
		if linkEscapes(p, target, root) {
			res = append(res, p+":escaping-symlink")
		}
	}
	for _, v := range values(out, "entry") {
		if v == "" {
			continue
		}
		// The type is bounded on the LEFT by the first colon (`entry=<type>:<path>`, type
		// first), because a path may legally contain one.
		etype, epath := "", ""
		if i := strings.Index(v, ":"); i >= 0 {
			etype, epath = v[:i], v[i+1:]
		}
		if epath != "" {
			switch {
			case etype == "special":
				res = append(res, epath+":special-entry")
				continue
			case etype == "symlink":
				if !ltpaths[epath] {
					res = append(res, epath+":missing-linktarget")
				}
				continue
			case entryTypes[etype]: // file | dir | hardlink — no core-required companion
				continue
			}
		}
		// A type outside the closed set, or an entry line with no path: refused, carrying the
		// RAW entry so the operator sees exactly what the copier emitted.
		res = append(res, v+":unknown-entry-type")
	}
	return res
}

// classifyRefusal parses `refused=<path>:<reason>` with the REASON LAST and taken from a CLOSED
// vocabulary, so a path containing a colon — legal on every filesystem this runs on — still
// parses. Splitting on the FIRST colon (the obvious way) reports `/src/a` as the refused path
// for `/src/a:b/dev/thing:special-entry`: the wrong path, in the one message an operator acts
// on. An unreadable refusal is still a refusal — reason "unreadable", carrying the raw value.
func classifyRefusal(v string) (reason, path, detail string) {
	// `foreign-uid` carries the numeric uid AFTER it, because a refusal that cannot say WHICH
	// uid is a refusal an operator cannot act on. Checked FIRST, and its failure to parse is
	// terminal rather than falling through to the suffix set: a value that both contains
	// `:foreign-uid:` and ends in another reason is a contradictory record, not a chance to
	// read the second-best answer out of it.
	if strings.Contains(v, ":foreign-uid:") {
		i := strings.LastIndex(v, ":")
		detail = v[i+1:]
		p := v[:i]
		if strings.HasSuffix(p, ":foreign-uid") {
			p = p[:strings.LastIndex(p, ":")]
		} else {
			p = ""
		}
		if detail == "" || !allDigits(detail) {
			p = ""
		}
		if p != "" {
			return "foreign-uid", p, detail
		}
		return "unreadable", v, ""
	}
	for _, r := range refusalReasons {
		if strings.HasSuffix(v, ":"+r) {
			return r, v[:len(v)-len(r)-1], ""
		}
	}
	return "unreadable", v, ""
}

// refusalMessage is the operator-facing wording for one refusal. THE REASONS ARE DISTINGUISHED
// DELIBERATELY: the message is the guard's product — a refusal an operator cannot act on has
// only half done its job — so each case says what was seen, why it is refused, and what the
// operator's next move is.
func refusalMessage(reason, path, detail, raw string) string {
	switch reason {
	case "special-entry":
		return fmt.Sprintf("copy: REFUSED %s — a device, socket or FIFO.\n"+
			"  These are not product data, cannot be meaningfully copied, and are the entry types a\n"+
			"  copier is most easily tricked by.", path)
	case "foreign-uid":
		return fmt.Sprintf("copy: REFUSED %s — it is owned by uid %s, which is neither the product's\n"+
			"  runtime uid nor yours. A foreign uid in a product volume is unexpected, and the\n"+
			"  decision is yours: re-run with --map-foreign-to-operator to fold them into the\n"+
			"  mapping (the numeric information is preserved in the report), or investigate first.", path, detail)
	case "escaped-write":
		return fmt.Sprintf("copy: REFUSED %s — the copier reported a write that would land outside the\n"+
			"  destination. This is the escape the confinement exists to prevent; the copy is abandoned.", path)
	case "escaping-symlink":
		return fmt.Sprintf("copy: REFUSED %s — its stored symlink target escapes the migrated tree (it is an\n"+
			"  absolute path, or climbs above the root with '..'). The copy preserves a target\n"+
			"  verbatim and does not resolve it, so carrying this one would point outside the tree\n"+
			"  the moment any later product or container followed it. Refused rather than kept.", path)
	case "staging-nonempty":
		return fmt.Sprintf("copy: REFUSED %s — the staging destination was not empty when the copy container\n"+
			"  reached it. Emptiness is checked INSIDE the container, on the writable mount and\n"+
			"  atomically with the copy: the copy MERGES the source over whatever is already there\n"+
			"  and verification checks only the source, so a pre-existing entry would survive inside\n"+
			"  the migrated tree unexamined. Refused.", path)
	case "unknown-entry-type":
		return fmt.Sprintf("copy: REFUSED %s — the copier enumerated an entry whose type is not one of file,\n"+
			"  dir, symlink, hardlink or special (or the entry line carries no path). An entry the\n"+
			"  core cannot classify — a FIFO or socket smuggled past the special-entry check — is\n"+
			"  refused rather than silently counted toward a copy reported complete.", path)
	case "unreadable-linktarget":
		return fmt.Sprintf("copy: REFUSED %s — the copier logged a symlink target this core could not read (its\n"+
			"  trailing length field is missing or not a number). A target we cannot parse might be\n"+
			"  concealing one that escapes the migrated tree, so it is refused rather than guessed.", path)
	case "missing-linktarget":
		return fmt.Sprintf("copy: REFUSED %s — the copier enumerated a symlink but disclosed no linktarget record\n"+
			"  for it, so its stored target was never shown and the escape backstop never ran on it. A\n"+
			"  symlink entry without a matching linktarget is refused: an undisclosed target cannot be\n"+
			"  shown not to escape the migrated tree.", path)
	case "unassociated-linktarget":
		return fmt.Sprintf("copy: REFUSED %s — the copier disclosed a linktarget for a path it did NOT enumerate\n"+
			"  as a symlink entry. A target with no symlink is a contradictory transcript — the\n"+
			"  linktarget-to-symlink relation is one-to-one — and is refused rather than trusted.", path)
	case "duplicate-linktarget":
		return fmt.Sprintf("copy: REFUSED %s — the copier disclosed MORE THAN ONE linktarget for one symlink. A\n"+
			"  symlink has exactly one stored target, so two is a contradiction (and lets a benign\n"+
			"  target be shown beside an escaping one). Refused rather than reading whichever one\n"+
			"  happens to be seen first.", path)
	default:
		return fmt.Sprintf("copy: REFUSED — the copier stated a refusal in a form this core cannot read: %q.\n"+
			"  It is treated as a refusal rather than skipped: an unreadable refusal is still one.", raw)
	}
}

// allDigits: the reference's `*[!0-9]*` test, which is a BYTE class — not unicode.IsDigit,
// which would accept every decimal digit in Unicode and hand a "number" to a parser that only
// understands ASCII.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
