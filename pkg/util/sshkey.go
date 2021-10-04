package util

import (
	"crypto"
	"io"

	"golang.org/x/crypto/ssh"
)

func SignatureFormatFromSigningOptionAndCA(opt string, ca ssh.PublicKey) string {
	switch {
	case ca != nil && ca.Type() == ssh.KeyAlgoED25519:
		return ssh.KeyAlgoED25519
	case ca != nil && ca.Type() == ssh.KeyAlgoRSA && opt == "":
		return ssh.SigAlgoRSA
	default:
		return opt
	}
}

type ExtendedAgentSigner interface {
	ssh.Signer
	SignWithOpts(rand io.Reader, data []byte, opts crypto.SignerOpts) (*ssh.Signature, error)
}

type ExtendedAgentSignerWrapper struct {
	Opts   crypto.SignerOpts
	Signer ExtendedAgentSigner
}

func (e *ExtendedAgentSignerWrapper) PublicKey() ssh.PublicKey {
	return e.Signer.PublicKey()
}

func (e *ExtendedAgentSignerWrapper) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return e.Signer.SignWithOpts(rand, data, e.Opts)
}

type AlgorithmSignerWrapper struct {
	Algorithm string
	Signer    ssh.AlgorithmSigner
}

func (a *AlgorithmSignerWrapper) PublicKey() ssh.PublicKey {
	return a.Signer.PublicKey()
}

func (a *AlgorithmSignerWrapper) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return a.Signer.SignWithAlgorithm(rand, data, a.Algorithm)
}
