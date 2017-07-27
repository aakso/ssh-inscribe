package server

import (
	"path"

	"github.com/aakso/ssh-inscribe/pkg/globals"
)

type AuthBackend struct {
	Type    string
	Config  string
	Default bool
}

type Config struct {
	Listen                    string
	TLSCertFile               string        `yaml:"TLSCertFile"`
	TLSKeyFile                string        `yaml:"TLSKeyFile"`
	AuthBackends              []AuthBackend `yaml:"authBackends"`
	DefaultAuthBackends       []string      `yaml:"defaultAuthBackends"`
	MaxCertLifetime           string        `yaml:"maxCertLifetime"`
	DefaultCertLifetime       string        `yaml:"defaultCertLifetime"`
	AgentSocket               string        `yaml:"agentSocket"`
	PKCS11Provider            string        `yaml:"pkcs11Provider"`
	PKCS11Pin                 string        `yaml:"pkcs11Pin"`
	CertSigningKeyFingerprint string        `yaml:"certSigningKeyFingerprint"`
	TokenSigningKey           string        `yaml:"tokenSigningKey"`
}

var Defaults *Config = &Config{
	Listen:      ":8540",
	TLSCertFile: "",
	TLSKeyFile:  "",
	AuthBackends: []AuthBackend{
		AuthBackend{
			Type:    "authfile",
			Config:  "authfile",
			Default: false,
		},
	},
	DefaultAuthBackends:       []string{},
	MaxCertLifetime:           "24h",
	DefaultCertLifetime:       "1h",
	AgentSocket:               path.Join(globals.VarDir(), "ssh_inscribe_agent.sock"),
	PKCS11Provider:            "",
	PKCS11Pin:                 "",
	CertSigningKeyFingerprint: "",
	TokenSigningKey:           "",
}
