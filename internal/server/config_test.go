package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeCert writes a self-signed certificate for dnsName and returns the
// certificate and key file paths.
func writeCert(t *testing.T, dir, dnsName string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	certFile = filepath.Join(dir, dnsName+".crt")
	keyFile = filepath.Join(dir, dnsName+".key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}

func leafName(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	return leaf.Subject.CommonName
}

func TestGetCertificateMapSingle(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCert(t, dir, "a.example.com")

	cc, err := Config{TLSCertFile: certFile, TLSKeyFile: keyFile}.GetCertificateMap()
	require.NoError(t, err)
	assert.Len(t, cc.Certificates, 1)
	assert.Empty(t, cc.CertificateMap)

	_, err = Config{TLSCertFile: certFile, TLSKeyFile: keyFile, TLSCertFiles: []string{certFile}}.GetCertificateMap()
	assert.Error(t, err, "TLSCertFile and TLSCertFiles are mutually exclusive")

	_, err = Config{TLSCertFile: certFile, TLSKeyFile: filepath.Join(dir, "missing")}.GetCertificateMap()
	assert.Error(t, err)
}

func TestGetCertificateMapNone(t *testing.T) {
	cc, err := Config{}.GetCertificateMap()
	require.NoError(t, err)
	assert.Empty(t, cc.Certificates, "no TLS configured")
}

func TestGetCertificateMapMultiple(t *testing.T) {
	dir := t.TempDir()
	aCert, aKey := writeCert(t, dir, "a.example.com")
	wCert, wKey := writeCert(t, dir, "wild.example.org")

	_, err := Config{
		TLSCertFiles: []string{aCert, wCert},
		TLSKeyFiles:  []string{aKey},
		TLSCertNames: []string{"a.example.com", "*.example.org"},
	}.GetCertificateMap()
	assert.Error(t, err, "list lengths must match")

	cc, err := Config{
		TLSCertFiles: []string{aCert, wCert},
		TLSKeyFiles:  []string{aKey, wKey},
		TLSCertNames: []string{"a.example.com", "*.example.org"},
	}.GetCertificateMap()
	require.NoError(t, err)
	require.Len(t, cc.Certificates, 2)

	for serverName, want := range map[string]string{
		"a.example.com":   "a.example.com",
		"A.Example.COM":   "a.example.com",
		"x.example.org":   "wild.example.org",
		"y.example.org":   "wild.example.org",
		"x.y.example.org": "",
		"b.example.com":   "",
		"":                "",
	} {
		cert, err := cc.GetCertificate(&tls.ClientHelloInfo{ServerName: serverName})
		require.NoError(t, err)
		if want == "" {
			assert.Nil(t, cert, "no match for %q, crypto/tls falls back to its default", serverName)
			continue
		}
		if assert.NotNil(t, cert, serverName) {
			assert.Equal(t, want, leafName(t, cert), serverName)
		}
	}
}
