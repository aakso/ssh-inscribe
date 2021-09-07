package client

import "time"

type Config struct {
	// URL selects an ssh-inscribe server to talk to
	URL string

	// Debug enables request debugging
	Debug bool

	// AlwaysRenew requests to renew even if current certificate is valid
	AlwaysRenew bool

	// IdentityFile selects private key to use to request certificate for
	IdentityFile string

	// CAKeyFile selects a CA private key file. Only used when adding initial signing key to the server
	CAKeyFile string

	// CAChallenge selects whether to request challenge for an encrypted CA private key
	CAChallenge bool

	// GenerateKeypair requests to generate ad-hoc keypair
	GenerateKeypair bool

	// GenerateKeypairType selects the generated key type, valid: rsa, ed25519
	GenerateKeypairType string

	// GenerateKeypairSize selects the generated key size, only valid for rsa
	GenerateKeypairSize int

	// WriteCert writes certificate to <IdentityFile>-cert.pub
	WriteCert bool

	// UseAgent requests to store key and certificate to a ssh-agent
	UseAgent bool

	// AgentConfirm requests certs and keys to be stored with confirm constraint
	AgentConfirm bool

	// Quiet disables printing to stdout
	Quiet bool

	// CertLifetime requests a specific certificate lifetime
	CertLifetime time.Duration

	// Insecure skips TLS validation for server connection
	Insecure bool

	// Timeout specifies the client timeout
	Timeout time.Duration

	// Retries specifies how many retries to do on failed requests. For example if the server timeouts
	Retries int

	// LoginAuthEndpoints selects which auth endpoints to login to
	LoginAuthEndpoints []string

	// IncludePrincipals requests only principals matching the pattern to be included
	IncludePrincipals string

	// ExcludePrincipals requests only principals not matching the pattern to be included
	ExcludePrincipals string

	// SigningOption sets an optional flag to be used in signing. This is only used if the CA's key is RSA.
	// If not, this option is silently ignored. Valid values: rsa-sha2-256 and rsa-sha2-512
	SigningOption string
}
