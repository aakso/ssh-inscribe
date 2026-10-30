package util

import (
	"math"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultRSAKeyAlgorithm is the default algorithm with RSA keys.
const DefaultRSAKeyAlgorithm = ssh.KeyAlgoRSASHA256

func SignatureFormatFromSigningOptionAndCA(opt string, ca ssh.PublicKey) string {
	switch {
	case ca != nil && ca.Type() == ssh.KeyAlgoED25519:
		return ssh.KeyAlgoED25519
	case ca != nil && ca.Type() == ssh.KeyAlgoRSA && opt == "":
		return DefaultRSAKeyAlgorithm
	default:
		return opt
	}
}

// maxCertTime is used for certificate timestamps beyond what time.Time can
// represent, e.g. ssh.CertTimeInfinity.
var maxCertTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// CertTimestamp converts t to an OpenSSH certificate timestamp. Times before
// the epoch are clamped to 0.
func CertTimestamp(t time.Time) uint64 {
	s := t.Unix()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// CertTime converts an OpenSSH certificate timestamp to time.Time.
func CertTime(v uint64) time.Time {
	if v > math.MaxInt64 || int64(v) >= maxCertTime.Unix() {
		return maxCertTime
	}
	return time.Unix(int64(v), 0)
}

// AgentLifetime returns the ssh-agent lifetime constraint in seconds for a
// certificate. 0 (no constraint) is only returned for certificates that
// never expire; already expired certificates get the shortest lifetime.
func AgentLifetime(cert *ssh.Certificate, now time.Time) uint32 {
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return 0
	}
	nowTS := CertTimestamp(now)
	if cert.ValidBefore <= nowTS {
		return 1
	}
	remaining := cert.ValidBefore - nowTS
	if remaining > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(remaining)
}
