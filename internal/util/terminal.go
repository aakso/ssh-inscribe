package util

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// TerminalSafe escapes control characters, bidirectional text controls and
// invalid UTF-8 in s, so that text from a server cannot send escape sequences
// to the user's terminal or hide what is printed. Newlines are escaped too.
func TerminalSafe(s string) string {
	if !strings.ContainsFunc(s, unsafeRune) {
		return s
	}
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r == utf8.RuneError: // a valid U+FFFD
			b.WriteRune(r)
		case unsafeRune(r) && r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
		s = s[size:]
	}
	return b.String()
}

// unsafeRune also matches utf8.RuneError, which strings.ContainsFunc reports
// for invalid UTF-8.
func unsafeRune(r rune) bool {
	return r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
}
