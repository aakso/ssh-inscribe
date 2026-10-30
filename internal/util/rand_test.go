package util

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandAlphanumeric(t *testing.T) {
	seen := map[rune]bool{}
	for range 200 {
		s := RandAlphanumeric(32)
		assert.Len(t, s, 32)
		for _, r := range s {
			assert.True(t, strings.ContainsRune(alphanumeric, r), "unexpected character %q", r)
			seen[r] = true
		}
	}
	// 6400 draws from 62 symbols: all of them should have appeared
	assert.Len(t, seen, len(alphanumeric))
	assert.Empty(t, RandAlphanumeric(0))
}

func TestRandB64(t *testing.T) {
	assert.NotEqual(t, RandB64(32), RandB64(32))
	assert.Len(t, RandBytes(17), 17)
}
