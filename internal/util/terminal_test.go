package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTerminalSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":                         "",
		"alice":                    "alice",
		"äö ✓ 日本":                  "äö ✓ 日本",
		"\x1b]0;title\x07":         `\x1b]0;title\x07`,
		"a\nb\rc\td":               `a\x0ab\x0dc\x09d`,
		"\x7f":                     `\x7f`,
		"\u009b31m":                `\x9b31m`,
		"\xff\xfe":                 `\xff\xfe`,
		"evil\u202egnp.exe":        `evil\u202egnp.exe`,
		"\ufffd is a valid rune":   "\ufffd is a valid rune",
		"key=\"x\" ok, principals": "key=\"x\" ok, principals",
	} {
		assert.Equal(t, want, TerminalSafe(in), "%q", in)
	}
}
