package backup

import (
	"fmt"
	"strings"
)

// The pinned helper's answer is a FLAT key=value transcript, and these are the four questions
// this module asks of one: does every line conform to the grammar this mode defines, was one
// observation STATED (whatever its value), does a problem key appear AT ALL, and what are the
// values of a repeated key.
//
// They live here rather than in the copy module because this module's refusals are specified
// against the transcript: which observation was missing, which mismatch names nothing, and the
// count that binds a verification to the manifest it claims to have checked. The seam carries
// the transcript; the reading of it is the refusal, and the refusal is this module's.

// body normalizes a helper's stdout the way the reference's command substitution does: every
// trailing newline is dropped, so a clean transcript yields no empty final line and an
// INTERIOR blank line is genuine evidence rather than an artefact of the capture.
func body(text string) string { return strings.TrimRight(text, "\n") }

// grammarOK holds the transcript to a CLOSED GRAMMAR: every non-empty line must be
// `<allowed-key>=<value>` for a key this mode expects. A line that matches nothing is not
// harmless — it could be an unparsed CONTINUATION of newline-bearing data, at which point the
// whole key=value record grammar is no longer reliable and none of the per-key checks below
// can be trusted. So a line outside the vocabulary FAILS CLOSED, naming the offending line.
//
// A WHOLLY-EMPTY TRANSCRIPT IS NOT THIS FUNCTION'S TO REFUSE: it is the "the helper reported
// nothing" case, which the stated-observation reader already refuses with a message that tells
// the operator WHICH observation was missing. Deferring it here keeps that diagnostic.
//
// A BLANK LINE IS NOT SKIPPED. Because the capture strips trailing newlines, a clean
// transcript has no empty line at all — so an interior blank line is genuine, and it can be
// the truncated continuation of a value that contained a newline, at which point the record
// boundaries are no longer trustworthy. It is refused as outside the grammar, not passed over.
func (d Deps) grammarOK(text string, allowed ...string) error {
	b := body(text)
	if b == "" {
		return nil
	}
	lines := strings.Split(b, "\n")
	hasContent := false
	for _, line := range lines {
		if line != "" {
			hasContent = true
			break
		}
	}
	if !hasContent {
		return nil
	}
	for _, line := range lines {
		if line == "" {
			d.warn("copy: the helper's transcript contains a blank line. A blank line can be the truncated")
			d.warn("  continuation of a value, so the record grammar is no longer reliable — refused.")
			return fmt.Errorf("copy: the helper's transcript contains a blank line")
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			d.warn("copy: the helper emitted a line that is not a key=value record: %q. The transcript", line)
			d.warn("  must be a closed grammar — an unrecognised line is refused, not ignored.")
			return fmt.Errorf("copy: the helper emitted a line that is not a key=value record: %q", line)
		}
		found := false
		for _, k := range allowed {
			if key == k {
				found = true
				break
			}
		}
		if !found {
			d.warn("copy: the helper emitted a line with an unexpected key: %q. Only the keys this", line)
			d.warn("  command defines are accepted; an unrecognised one is refused rather than ignored.")
			return fmt.Errorf("copy: the helper emitted a line with an unexpected key: %q", line)
		}
	}
	return nil
}

// stated is THE VALUE OF ONE STATED OBSERVATION, or a refusal — and it is the one place
// "absent is not ok" lives. An empty value is a real answer and is handed back as one; not
// stated at all, or stated TWICE, refuses.
//
// THE DUPLICATE RULE IS THE READER'S, NOT EACH CALLER'S: the flat response format gives a
// repeated key no meaning — an answer that says `done=ok` and then `done=fail` does not say
// `ok`, it says two things, and it is malformed evidence. Every line is read, never stopping
// at the first hit: a reader that returns early cannot see the second copy, which is precisely
// the evidence it must refuse on.
//
// noun only NAMES the observation in the refusal, so an operator is told what was missing
// rather than which key spells it.
func (d Deps) stated(text, key, what, noun string) (string, error) {
	if noun == "" {
		noun = fmt.Sprintf("the %q observation", key)
	}
	val := ""
	seen := 0
	for _, line := range strings.Split(body(text), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			val = v
			seen++
		}
	}
	if seen > 1 {
		d.warn("copy: the %s helper states %q %d times, and the answer format gives a repeated field no", what, key+"=", seen)
		d.warn("  meaning — an answer that says a thing twice says two things. REFUSED as ambiguous.")
		return "", fmt.Errorf("copy: the %s helper states %q more than once", what, key+"=")
	}
	if seen == 0 {
		d.warn("copy: the %s helper stated nothing about %s.", what, noun)
		d.warn("  Refusing: a missing observation is not a passing one — unmeasured is not measured-clean.")
		return "", fmt.Errorf("copy: the %s helper stated nothing about %s", what, noun)
	}
	return val, nil
}

// fields returns every value for a REPEATED key, in order. The repeated keys are the copy's
// own vocabulary — `mismatch` here — where a second copy of the key is a second OBSERVATION
// rather than a contradiction, which is why they are read here and not through the
// single-value reader above.
func fields(text, key string) []string {
	var out []string
	for _, line := range strings.Split(body(text), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			out = append(out, v)
		}
	}
	return out
}

// hasKey answers whether <key> is stated AT ALL, whatever its value — including an empty one.
// A problem record (`mismatch=`) is a problem by its PRESENCE, so it must be detected by the
// key, not by iterating its values: a value-iterating loop that skips empty strings then skips
// exactly the problem it was meant to catch.
func hasKey(text, key string) bool {
	for _, line := range strings.Split(body(text), "\n") {
		if strings.HasPrefix(line, key+"=") {
			return true
		}
	}
	return false
}
