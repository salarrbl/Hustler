package cve

import (
	"strconv"
	"strings"
)

// Version handling for CVE range matching.
//
// retire.js semantics: an entry is vulnerable for versions v where
// v >= atOrAbove (if set) AND v < below (if set).
// Legacy entries only carry MaxVersion, which is treated as `below`
// with no lower bound.

// normalizeVersion strips common decorations: leading v/V/=, whitespace
// and build metadata (+...). It keeps pre-release markers for comparison.
func normalizeVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	s = strings.TrimPrefix(s, "=")
	if i := strings.Index(s, "+"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// splitPreRelease separates "1.2.3-beta1" into ("1.2.3", "beta1").
// A version without "-" has no dash pre-release.
func splitPreRelease(s string) (string, string) {
	if i := strings.Index(s, "-"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// splitVersion returns numeric components (padded to at least 3) and a
// pre-release marker ("" for final releases).
//
// A single trailing letter on the last component is an OpenSSL-style patch
// level, not a pre-release: "1.0.1e" becomes [1,0,1,5] so that
// 1.0.1 < 1.0.1e < 1.0.1f. Any other leftover ("b1", "rc2", "min")
// marks a pre-release, which is older than the same numeric release.
func splitVersion(s string) ([]int, string) {
	s = normalizeVersion(s)
	pre := ""
	if core, rest := splitPreRelease(s); rest != "" {
		s = core
		pre = rest
	}
	raw := strings.Split(s, ".")
	out := make([]int, 0, len(raw)+1)
	for i, p := range raw {
		p = strings.TrimSpace(p)
		if p == "" {
			out = append(out, 0)
			continue
		}
		n, leftover := parseComponentStr(p)
		out = append(out, n)
		if leftover != "" {
			if i == len(raw)-1 && len(leftover) == 1 && isASCIILetter(leftover[0]) {
				out = append(out, int(leftover[0]|0x20-'a')+1)
			} else if pre == "" {
				pre = leftover
			}
		}
	}
	for len(out) < 3 {
		out = append(out, 0)
	}
	return out, pre
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// parseComponentStr parses leading digits and returns the leftover suffix.
func parseComponentStr(c string) (int, string) {
	i := 0
	for i < len(c) && c[i] >= '0' && c[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, c
	}
	n, _ := strconv.Atoi(c[:i])
	return n, c[i:]
}

// compareVersionStrings compares two version strings.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
// A pre-release is always older than the same numeric release; two
// pre-releases compare lexically ("b1" < "rc1").
func compareVersionStrings(a, b string) int {
	pa, prea := splitVersion(a)
	pb, preb := splitVersion(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] < pb[i] {
			return -1
		}
		if pa[i] > pb[i] {
			return 1
		}
	}
	if len(pa) != len(pb) {
		// Longer numeric tail wins only if it has non-zero parts.
		longer, shorter := pa, pb
		if len(pb) > len(pa) {
			longer, shorter = pb, pa
		}
		for _, v := range longer[len(shorter):] {
			if v != 0 {
				if len(pa) > len(pb) {
					return 1
				}
				return -1
			}
		}
	}
	switch {
	case prea == "" && preb == "":
		return 0
	case prea == "":
		return 1
	case preb == "":
		return -1
	case prea < preb:
		return -1
	case prea > preb:
		return 1
	default:
		return 0
	}
}

// versionLess reports a < b.
func versionLess(a, b string) bool {
	return compareVersionStrings(a, b) < 0
}

// versionGTE reports a >= b.
func versionGTE(a, b string) bool {
	return compareVersionStrings(a, b) >= 0
}

// versionInRange reports whether detected is vulnerable given an
// [atOrAbove, below) interval. Empty bounds (or "*") mean unbounded.
// An exact-version entry (atOrAbove == below) matches that version only.
func versionInRange(detected, atOrAbove, below string) bool {
	detected = strings.TrimSpace(detected)
	if detected == "" || detected == "*" {
		return false
	}
	a := strings.TrimSpace(atOrAbove)
	b := strings.TrimSpace(below)
	if a != "" && a != "*" && a == b {
		return compareVersionStrings(detected, a) == 0
	}
	if a != "" && a != "*" {
		if !versionGTE(detected, a) {
			return false
		}
	}
	if b != "" && b != "*" {
		if !versionLess(detected, b) {
			return false
		}
	}
	// Fully unbounded entries carry no version gate: they are advisory
	// records, not auto-matches.
	if (a == "" || a == "*") && (b == "" || b == "*") {
		return false
	}
	return true
}

// entryMatchesVersion reports whether a detected version falls inside a
// database entry's vulnerable range, honouring both the modern
// (AtOrAbove/FixedVersion) and legacy (MaxVersion) encodings.
func entryMatchesVersion(detected string, e LocalCVEEntry) bool {
	below := e.FixedVersion
	if below == "" {
		below = e.MaxVersion
	}
	return versionInRange(detected, e.AtOrAbove, below)
}
