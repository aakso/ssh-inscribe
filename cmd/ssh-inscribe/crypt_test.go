package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword([]byte("secret"))
	if assert.NoError(t, err) {
		assert.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte("secret")))
	}

	_, err = hashPassword(nil)
	assert.Error(t, err, "empty passwords cannot be used with authfile")
}

func TestReadLine(t *testing.T) {
	for in, want := range map[string]string{
		"secret\n":      "secret",
		"secret\r\n":    "secret",
		"secret":        "secret",
		"first\nsecond": "first",
		"":              "",
	} {
		got, err := readLine(strings.NewReader(in))
		assert.NoError(t, err)
		assert.Equal(t, want, string(got), "input %q", in)
	}
}
