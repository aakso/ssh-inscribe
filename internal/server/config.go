package server

import (
	"crypto/tls"
	"path"

	"github.com/aakso/ssh-inscribe/internal/globals"

	"github.com/pkg/errors"
)

type CertificateConfig struct {
	Certificates   []tls.Certificate
	CertificateMap map[string]*tls.Certificate
}

type AuthBackend struct {
	Type    string
	Config  string
	Default bool
}

type Config struct {
	Listen                    string
	TLSCertFile               string        `yaml:"TLSCertFile"`
	TLSKeyFile                string        `yaml:"TLSKeyFile"`
	TLSCertFiles              []string      `yaml:"TLSCertFiles"`
	TLSKeyFiles               []string      `yaml:"TLSKeyFiles"`
	TLSCertNames              []string      `yaml:"TLSCertNames"`
	AuthBackends              []AuthBackend `yaml:"authBackends"`
	DefaultAuthBackends       []string      `yaml:"defaultAuthBackends"`
	MaxCertLifetime           string        `yaml:"maxCertLifetime"`
	DefaultCertLifetime       string        `yaml:"defaultCertLifetime"`
	CaChallengeLifetime       string        `yaml:"caChallengeLifetime"`
	AgentSocket               string        `yaml:"agentSocket"`
	PKCS11Provider            string        `yaml:"pkcs11Provider"`
	PKCS11Pin                 string        `yaml:"pkcs11Pin"`
	CertSigningKeyFingerprint string        `yaml:"certSigningKeyFingerprint"`
	TokenSigningKey           string        `yaml:"tokenSigningKey"`
}

var Defaults *Config = &Config{
	Listen:       ":8540",
	TLSCertFile:  "",
	TLSKeyFile:   "",
	TLSCertFiles: []string{},
	TLSKeyFiles:  []string{},
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
	CaChallengeLifetime:       "5m",
	AgentSocket:               path.Join(globals.VarDir(), "ssh_inscribe_agent.sock"),
	PKCS11Provider:            "",
	PKCS11Pin:                 "",
	CertSigningKeyFingerprint: "",
	TokenSigningKey:           "",
}

func (c Config) GetCertificateMap() (cc CertificateConfig, err error) {
	cc = CertificateConfig{
		Certificates:   []tls.Certificate{},
		CertificateMap: make(map[string]*tls.Certificate),
	}

	// Single certificate has no name configuration
	if c.TLSCertFile != "" && c.TLSKeyFile != "" {
		if len(c.TLSCertFiles) > 0 {
			return cc, errors.New("Unsupported configuration, either set TLSCertFile or TLSCertFiles, not both")
		}

		var certificate, err = tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return cc, err
		}
		cc.Certificates = append(cc.Certificates, certificate)
		return cc, nil
	}

	if len(c.TLSCertFiles) > 0 && len(c.TLSKeyFiles) > 0 && len(c.TLSCertNames) > 0 {
		if (len(c.TLSCertFiles) != len(c.TLSKeyFiles)) || (len(c.TLSCertFiles) != len(c.TLSCertNames)) {
			return cc, errors.New("TLSCertFiles, TLSKeyFiles and TLSCertNames must contain same number of elements")
		}

		cc.Certificates = make([]tls.Certificate, len(c.TLSCertFiles))
		for index, cert := range c.TLSCertFiles {
			var certificate, err = tls.LoadX509KeyPair(cert, c.TLSKeyFiles[index])
			if err != nil {
				return cc, err
			}
			cc.Certificates[index] = certificate
			cc.CertificateMap[c.TLSCertNames[index]] = &cc.Certificates[index]
		}
		return cc, nil
	}
	return cc, nil
}
