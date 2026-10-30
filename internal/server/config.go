package server

import (
	"crypto/tls"
	"errors"
	"path"
	"strings"

	"github.com/aakso/ssh-inscribe/internal/globals"
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

var Defaults = &Config{
	Listen:       ":8540",
	TLSCertFile:  "",
	TLSKeyFile:   "",
	TLSCertFiles: []string{},
	TLSKeyFiles:  []string{},
	AuthBackends: []AuthBackend{
		{
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

// GetCertificate selects a certificate by the TLS server name, exactly or by
// a wildcard for the first label, like the deprecated
// tls.Config.NameToCertificate did. It returns nil when there is no match so
// that crypto/tls falls back to its default selection.
func (cc CertificateConfig) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(hello.ServerName)
	if cert, ok := cc.CertificateMap[name]; ok {
		return cert, nil
	}
	if name != "" {
		labels := strings.Split(name, ".")
		labels[0] = "*"
		if cert, ok := cc.CertificateMap[strings.Join(labels, ".")]; ok {
			return cert, nil
		}
	}
	return nil, nil
}

func (c Config) GetCertificateMap() (cc CertificateConfig, err error) {
	cc = CertificateConfig{
		Certificates:   []tls.Certificate{},
		CertificateMap: make(map[string]*tls.Certificate),
	}

	// Single certificate has no name configuration
	if c.TLSCertFile != "" && c.TLSKeyFile != "" {
		if len(c.TLSCertFiles) > 0 {
			return cc, errors.New("unsupported configuration, either set TLSCertFile or TLSCertFiles, not both")
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
