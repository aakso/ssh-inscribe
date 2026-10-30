package util

import (
	"crypto/rand"
	"encoding/base64"
)

func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func RandB64(n int) string {
	return base64.StdEncoding.EncodeToString(RandBytes(n))
}

const alphanumeric = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// RandAlphanumeric returns n uniformly distributed alphanumeric characters
// from crypto/rand.
func RandAlphanumeric(n int) string {
	// Reject bytes >= 248 (the largest multiple of 62 <= 256) to avoid
	// modulo bias.
	const limit = 256 - 256%len(alphanumeric)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		_, _ = rand.Read(buf)
		for _, c := range buf {
			if int(c) < limit && len(out) < n {
				out = append(out, alphanumeric[int(c)%len(alphanumeric)])
			}
		}
	}
	return string(out)
}
