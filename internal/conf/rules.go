package conf

import (
	"strconv"
	"strings"

	"mythicalos.ai/ctl/internal/layout"
)

// ValueOK: printable ASCII (space included) and every byte >= 0x80, so a UTF-8 path such as
// /Users/José/work is accepted — refusing non-ASCII would break real operators and buys
// nothing, because the danger is control and shell metacharacters, not accents. Refused in
// addition: $ ` \ — inert here (nothing is ever expanded) but no legitimate value needs them,
// and their absence is what lets a reader stop worrying. No leading/trailing space, so the
// round-trip is unambiguous. This is ALSO the write path's validator: a newline here is
// exactly D19's "a value containing a newline must not be able to forge a second key". The
// caps are BYTES, never locale-dependent character counts.
func ValueOK(v string) bool {
	if len(v) > MaxLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		b := v[i]
		if b < 0x20 || b == 0x7f || b == '$' || b == '`' || b == '\\' {
			return false
		}
	}
	if strings.HasPrefix(v, " ") || strings.HasSuffix(v, " ") {
		return false
	}
	return true
}

// KeyOK: MYTHICAL_ followed by one or more of [A-Z0-9_]; at most 128 bytes.
func KeyOK(k string) bool {
	if len(k) > 128 {
		return false
	}
	rest, ok := strings.CutPrefix(k, "MYTHICAL_")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		b := rest[i]
		if (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' {
			return false
		}
	}
	return true
}

// intOK is the decimal range check, textual-first so no width surprises: all digits, no sign,
// no space; a leading zero is refused — the bash `[ -ge ]` would have re-read `010` as octal 8,
// and a value textually out of range must not validate by being read as a different number;
// at most 18 digits.
func intOK(v string, min, max int64) bool {
	if v == "" || len(v) > 18 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	if len(v) > 1 && v[0] == '0' {
		return false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return false
	}
	return n >= min && n <= max
}

// TypeOK validates one value against one spec type: str:N, int:MIN:MAX, bool, enum:a|b|c,
// path:N, netname. Unknown types refuse (an unknown spec type is a spec bug, and a spec bug
// must not validate anything). The caps are BYTES.
func TypeOK(typ, v string) bool {
	switch {
	case strings.HasPrefix(typ, "str:"):
		n, err := strconv.Atoi(typ[4:])
		return err == nil && len(v) <= n
	case strings.HasPrefix(typ, "int:"):
		rest := typ[4:]
		lo, hi, ok := strings.Cut(rest, ":")
		if !ok {
			return false
		}
		min, err1 := strconv.ParseInt(lo, 10, 64)
		max, err2 := strconv.ParseInt(hi, 10, 64)
		return err1 == nil && err2 == nil && intOK(v, min, max)
	case typ == "bool":
		return v == "true" || v == "false"
	case strings.HasPrefix(typ, "enum:"):
		if v == "" {
			return false
		}
		// A value that CONTAINS the delimiter would forge a match against the JOINED list
		// rather than a member of it (v = "red|green" against enum:red|green). The format has
		// no escaping, so no member can legitimately contain '|'; refuse the delimiter first.
		if strings.Contains(v, "|") {
			return false
		}
		for _, m := range strings.Split(typ[5:], "|") {
			if v == m {
				return true
			}
		}
		return false
	case strings.HasPrefix(typ, "path:"):
		n, err := strconv.Atoi(typ[5:])
		if err != nil || v == "" || !strings.HasPrefix(v, "/") || len(v) > n {
			return false
		}
		// Reject a `..` PATH COMPONENT, not the substring: /srv/..hidden is a legitimate name.
		return !strings.Contains("/"+v+"/", "/../")
	case typ == "netname":
		// Docker network name: [A-Za-z0-9] then [A-Za-z0-9_.-]*. Additionally refuse the two
		// special modes §4b.2 bans — `host` shares the host network namespace outright, and
		// `container:<name>` joins another container's. `none` likewise. Neither is a network
		// this installer may own.
		if v == "" || len(v) > 128 {
			return false
		}
		if v == "host" || v == "none" || strings.HasPrefix(v, "container:") {
			return false
		}
		if !isAlnum(v[0]) {
			return false
		}
		for i := 1; i < len(v); i++ {
			b := v[i]
			if !isAlnum(b) && b != '_' && b != '.' && b != '-' {
				return false
			}
		}
		return true
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// BindKeyType recognises THE ONE product-scoped shape the core accepts by pattern rather than
// by name: `MYTHICAL_<PRODUCT>_<ROLE>_BIND`, the key migrate-storage writes. Format only —
// whether THIS product/role may be bound is the entitlement's question, asked upstream, never
// re-decided here. Returns ("path:4096", true) for the shape, ("", false) otherwise.
func BindKeyType(key string) (string, bool) {
	mid, ok := strings.CutPrefix(key, "MYTHICAL_")
	if !ok {
		return "", false
	}
	mid, ok = strings.CutSuffix(mid, "_BIND")
	if !ok || mid == "" {
		return "", false
	}
	for i := 0; i < len(mid); i++ {
		b := mid[i]
		if (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' {
			return "", false
		}
	}
	// PRODUCT and ROLE, joined by the '_' this shape needs.
	if !strings.Contains(mid, "_") {
		return "", false
	}
	return "path:4096", true
}

// ProductNameOK re-exports the grammar's one authority (internal/layout) so conf callers and
// tests reach it through this package the way the bash reached _mi_conf_product_name_ok —
// same function, no second implementation.
func ProductNameOK(p string) bool { return layout.ProductNameOK(p) }
