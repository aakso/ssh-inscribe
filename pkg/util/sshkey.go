package util

import (
	"golang.org/x/crypto/ssh"
)

func SignatureFormatFromSigningOptionAndCA(opt string, ca ssh.PublicKey) string {
	switch {
	case ca != nil && ca.Type() == ssh.KeyAlgoED25519:
		return ssh.KeyAlgoED25519
	case ca != nil && ca.Type() == ssh.KeyAlgoRSA && opt == "":
		return ssh.KeyAlgoRSASHA256
	default:
		return opt
	}
}
