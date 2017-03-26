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
