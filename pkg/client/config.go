package client

import "time"

type Config struct {
	URL   string
	Debug bool

	// Always renew even if current certificate is valid
	AlwaysRenew bool

	// Path to private key file to use, if empty, generate a new key
	IdentityFile string

	// Path to CA private key file. Only used when adding initial signing key to the server
	CAKeyFile string

	// Generate ad-hoc keypair
	GenerateKeypair bool

	// Generated key type, valid: rsa, ed25519
	GenerateKeypairType string

	// Generated key size, only valid for rsa
	GenerateKeypairSize int

	// Write certificate to <IdentityFile>-cert.pub
	WriteCert bool

	// Store key and certificate to a ssh-agent
	UseAgent bool

	// Store certs and keys with confirm constraint
	AgentConfirm bool

	// Do not print anything
	Quiet bool

	// Request specific certificate lifetime
	CertLifetime time.Duration

	// Skip TLS validation for server connection
	Insecure bool

	// Client timeout
	Timeout time.Duration

	// How many retries on failed requests
	// For example if the server timeouts
	Retries int

	// Which auth endpoints to login to
	LoginAuthEndpoints []string

	// Request only principals matching the pattern to be included
	IncludePrincipals string

	// Request only principals not matching the pattern to be included
	ExcludePrincipals string
}
