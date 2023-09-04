package util

import (
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
