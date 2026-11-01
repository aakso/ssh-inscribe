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

func TestSplitUnsafePrincipals(t *testing.T) {
	safe, unsafe := SplitUnsafePrincipals([]string{"b", "x,admins", "a", "", "c\n"})
	assert.Equal(t, []string{"b", "a"}, safe)
	assert.Equal(t, []string{"x,admins", "", "c\n"}, unsafe)

	safe, unsafe = SplitUnsafePrincipals(nil)
	assert.Empty(t, safe)
	assert.Empty(t, unsafe)
}
