package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnsafePrincipal(t *testing.T) {
	for _, p := range []string{"alice", "my.company.example.com-SEC_DEV", "Sales EMEA", "user@example.com"} {
		assert.False(t, UnsafePrincipal(p), p)
	}
	for _, p := range []string{"", "a,b", "Sales, EMEA", "a\nb", "a\x00b"} {
		assert.True(t, UnsafePrincipal(p), p)
	}
}
