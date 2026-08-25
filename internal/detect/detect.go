// Package detect reads the /detect version contract (D10, §9) — CONSUMER side only.
//
// /detect is JSON and is not ours to change. The core needs exactly three flat string fields
// from it — product, version, ui_url.
//
// THIS IS NOT A JSON PARSER, and it must not grow into one. It is a bounded state machine —
// string state, brace/bracket depth, and nothing else — that locates depth-1 members over RAW
// bytes and says honestly which values it cannot read: any escape, a raw control byte, a
// non-string value, a nested object all flag unreadable rather than being decoded or guessed
// at. Working on raw spans is the point (the rewrite plan's round-3 correction): a decoding
// tokenizer makes a literal `"product"` and an escaped `"product"` indistinguishable,
// and this reader must refuse the escaped spelling, never match it.
package detect

import (
	"errors"
	"fmt"
	"regexp"
)

// Unknown is the explicit no-version marker: never fabricated FROM anything, never inherited
// from a sibling field — unmeasured is not measured-clean (§9).
const Unknown = "unknown"

// MaxBytes bounds the whole response BEFORE the scan: the input is a live HTTP reply from a
// product container, so an unbounded scan is a stall the product controls. (The bash carried a
// measured BSD-awk quadratic here; Go's scan is linear, the cap stays because the input is
// attacker-paced either way.) 32 KiB is generous for three short flat strings.
const MaxBytes = 32768

// ErrAbsent — the field does not appear at the top level (the rc-3 analogue), distinct from
// every unreadable case.
var ErrAbsent = errors.New("field is absent")

// member is one depth-1 record: flag 's' (a plain string read verbatim), 'e' (a string this
// reader cannot read verbatim — an escape or raw control byte appeared in the key or value),
// 'x' (not a plain string: object, array, number, bool, null).
type member struct {
	key  string
	flag byte
	val  string
}

var litRe = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?$`)

func litOK(v string) bool {
	return v == "true" || v == "false" || v == "null" || litRe.MatchString(v)
}

// scan walks the raw bytes with the reference's exact state machine. Returns the depth-1
// members and whether the document as a whole is readable (an unterminated string, unbalanced
// or mismatched nesting, an invalid escape, a raw control byte in a string, bad member
// sequencing, or trailing content all make it unreadable — and any lookup against such a
// response is unreadable, never absent).
func scan(data []byte) (members []member, wellFormed bool) {
	var stack []byte
	instr, esc := false, false
	ux := 0
	st := 0 // 0 expect-first-key 1 have-key 2 expect-value 3 value-done 4 in-literal 5 expect-key-after-comma
	var key, tok, lit []byte
	keybad, bad := false, false
	errFlag, closed := false, false

	depth := func() int { return len(stack) }
	for i := 0; i < len(data); i++ {
		c := data[i]

		if instr {
			if c == '\n' {
				errFlag = true // a raw LF inside a string
				continue
			}
			if ux > 0 {
				if !isHex(c) {
					errFlag = true
				}
				ux--
				bad = true
				continue
			}
			if esc {
				esc = false
				bad = true // the value is unreadable verbatim either way
				if c == 'u' {
					ux = 4
					continue
				}
				switch c {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				default:
					errFlag = true // an invalid escape is malformed JSON
				}
				continue
			}
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				instr = false
				if depth() == 1 && (st == 0 || st == 5) {
					key = append([]byte{}, tok...)
					keybad = bad
					st = 1
				} else if depth() == 1 && st == 2 {
					if bad || keybad {
						members = append(members, member{string(key), 'e', ""})
					} else {
						members = append(members, member{string(key), 's', string(tok)})
					}
					st = 3
				}
				tok = tok[:0]
				bad = false
				continue
			}
			if c < ' ' {
				errFlag = true // a raw control byte inside a string
				continue
			}
			tok = append(tok, c)
			continue
		}

		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			if st == 4 { // whitespace ends a bare literal
				if !litOK(string(lit)) {
					errFlag = true
				}
				lit = lit[:0]
				st = 3
			}
			continue
		}

		if depth() == 0 {
			if closed || c != '{' {
				errFlag = true
				continue
			}
			stack = append(stack, '}')
			st = 0
			continue
		}

		if depth() == 1 {
			if st == 4 { // consuming a bare literal
				if c == ',' || c == '}' {
					if !litOK(string(lit)) {
						errFlag = true
					}
					lit = lit[:0]
					st = 3
				} else {
					lit = append(lit, c)
					continue
				}
			}
			switch st {
			case 0, 5: // a key; after ',' (st 5) it is REQUIRED
				if c == '}' && st == 0 {
					stack = stack[:0]
					closed = true
					continue
				}
				if c == '"' {
					instr = true
					tok = tok[:0]
					bad = false
					continue
				}
				errFlag = true
				continue
			case 1:
				if c == ':' {
					st = 2
					continue
				}
				errFlag = true
				continue
			case 2:
				switch c {
				case '"':
					instr = true
					tok = tok[:0]
					bad = false
				case '{':
					members = append(members, member{string(key), 'x', ""})
					stack = append(stack, '}')
				case '[':
					members = append(members, member{string(key), 'x', ""})
					stack = append(stack, ']')
				default:
					members = append(members, member{string(key), 'x', ""})
					lit = append(lit[:0], c)
					st = 4
				}
				continue
			case 3: // a value consumed; ONLY a comma or the closing brace may follow
				if c == ',' {
					st = 5
					continue
				}
				if c == '}' {
					stack = stack[:0]
					closed = true
					continue
				}
				errFlag = true
				continue
			}
		}

		// depth >= 2: values we deliberately do not interpret — but DELIMITERS ARE STILL
		// MATCHED: mismatched nesting would desynchronise the depth counter and let a nested
		// key be reported as top-level, the one way malformed input elsewhere could make this
		// reader answer wrongly.
		switch c {
		case '{':
			stack = append(stack, '}')
		case '[':
			stack = append(stack, ']')
		case '}', ']':
			if len(stack) == 0 || stack[len(stack)-1] != c {
				errFlag = true
				continue
			}
			stack = stack[:len(stack)-1]
			if depth() == 1 {
				st = 3
			}
			if depth() == 0 {
				closed = true
			}
		case '"':
			instr = true
			tok = tok[:0]
			bad = false
		}
	}
	if st == 4 && !litOK(string(lit)) {
		errFlag = true
	}
	if instr || depth() != 0 || errFlag || !closed {
		return members, false
	}
	return members, true
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// Field extracts a flat, top-level string field. errors.Is(ErrAbsent) is the rc-3 branch;
// every other error means unreadable — an ambiguous repeat of the REQUESTED field included
// (a repeat of a different field does not poison this lookup).
func Field(jsonBody []byte, field string) (string, error) {
	if field == "" || !fieldNameOK(field) {
		return "", fmt.Errorf("detect: %q is not a field name", field)
	}
	if len(jsonBody) > MaxBytes {
		return "", fmt.Errorf("detect: the response is %d bytes, more than %d — refusing to parse it", len(jsonBody), MaxBytes)
	}
	members, wellFormed := scan(jsonBody)
	if !wellFormed {
		return "", errors.New("detect: the response is not well-formed enough to read (unterminated string, unbalanced braces or trailing content)")
	}
	var hits []member
	for _, m := range members {
		if m.key == field {
			hits = append(hits, m)
		}
	}
	switch {
	case len(hits) == 0:
		return "", fmt.Errorf("detect: %q: %w", field, ErrAbsent)
	case len(hits) > 1:
		return "", fmt.Errorf("detect: %q appears %d times at the top level — refusing an ambiguous response", field, len(hits))
	}
	if hits[0].flag != 's' {
		return "", fmt.Errorf("detect: the value of %q is not a plain string this reader can extract (escapes, numbers, null and nested objects are refused rather than guessed at)", field)
	}
	return hits[0].val, nil
}

func fieldNameOK(f string) bool {
	for i := 0; i < len(f); i++ {
		b := f[i]
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return true
}

// Version implements D10's three-way fallback: `version` preferred; `image_version` is a
// DEPRECATED ALIAS consulted for exactly two of the three ways `version` can come back —
// ABSENT, and present-but-EMPTY. Present-but-UNREADABLE never falls back: something WAS
// reported and this reader failed to read it, and answering with a different field's value
// would mask that — it reports Unknown instead. An image with no stamp reports the explicit
// Unknown marker; it never fabricates a value and never inherits a sibling's.
func Version(jsonBody []byte) string {
	v, err := Field(jsonBody, "version")
	if err == nil && v != "" {
		return v
	}
	if err != nil && !errors.Is(err, ErrAbsent) {
		return Unknown // present but unreadable: the one case that must not fall back
	}
	if v, err := Field(jsonBody, "image_version"); err == nil && v != "" {
		return v
	}
	return Unknown
}
