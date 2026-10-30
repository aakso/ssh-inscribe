package util

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestCertTimestamp(t *testing.T) {
	assert.Equal(t, uint64(0), CertTimestamp(time.Unix(-5, 0)))
	assert.Equal(t, uint64(1700000000), CertTimestamp(time.Unix(1700000000, 0)))
}

func TestCertTime(t *testing.T) {
	assert.Equal(t, time.Unix(1700000000, 0), CertTime(1700000000))
	assert.Equal(t, maxCertTime, CertTime(ssh.CertTimeInfinity))
	assert.Equal(t, maxCertTime, CertTime(math.MaxInt64))
	assert.Equal(t, maxCertTime, CertTime(CertTimestamp(maxCertTime)))
	assert.Equal(t, uint64(0), CertTimestamp(CertTime(0)))
}

func TestAgentLifetime(t *testing.T) {
	now := time.Unix(1700000000, 0)
	cert := func(validBefore uint64) *ssh.Certificate {
		return &ssh.Certificate{ValidBefore: validBefore}
	}
	assert.Equal(t, uint32(3600), AgentLifetime(cert(CertTimestamp(now.Add(time.Hour))), now))
	assert.Equal(t, uint32(0), AgentLifetime(cert(ssh.CertTimeInfinity), now), "never expiring")
	assert.Equal(t, uint32(1), AgentLifetime(cert(CertTimestamp(now)), now), "expires now")
	assert.Equal(t, uint32(1), AgentLifetime(cert(CertTimestamp(now.Add(-time.Hour))), now), "already expired")
	assert.Equal(t, uint32(1), AgentLifetime(cert(0), now), "zero timestamp is in the past")
	assert.Equal(t, uint32(math.MaxUint32), AgentLifetime(cert(math.MaxUint64-1), now), "clamped")
}

func TestSignatureFormatFromSigningOptionAndCA(t *testing.T) {
	ed := mustParsePublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEX4yJ7wA17a7yS1HhR0b6n5pV/9pXz5oV/1lJ2C6s1M")
	rsaKey := mustParsePublicKey(t, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDC5Wa4fvIYDLVUVBZGBA6Cp6wGtZ6O+e0yOQNZ0RcOnq+mItEy4XkRhcRaGbkoGJpXDEfOJcUiX8CYb2hQp5ilDRxzjX/CKQlYc9XukGvYsvTTvtCkLQbz6nWVKpGLy5cYpTGfp+8HVIl9a8kuLr2ozaUZTAyGrjdPIbG2czYNUQ==")
	assert.Equal(t, ssh.KeyAlgoED25519, SignatureFormatFromSigningOptionAndCA("", ed))
	assert.Equal(t, ssh.KeyAlgoED25519, SignatureFormatFromSigningOptionAndCA(ssh.KeyAlgoRSASHA512, ed))
	assert.Equal(t, DefaultRSAKeyAlgorithm, SignatureFormatFromSigningOptionAndCA("", rsaKey))
	assert.Equal(t, ssh.KeyAlgoRSASHA512, SignatureFormatFromSigningOptionAndCA(ssh.KeyAlgoRSASHA512, rsaKey))
	assert.Equal(t, ssh.KeyAlgoRSA, SignatureFormatFromSigningOptionAndCA(ssh.KeyAlgoRSA, rsaKey))
	assert.Equal(t, "opt", SignatureFormatFromSigningOptionAndCA("opt", nil))
}

func mustParsePublicKey(t *testing.T, s string) ssh.PublicKey {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return k
}
