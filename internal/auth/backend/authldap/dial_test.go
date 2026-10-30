package authldap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlsListener accepts TLS connections with a self-signed certificate and
// completes the handshake; it never speaks LDAP.
func tlsListener(t *testing.T) net.Listener {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tln := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tln.Close() })
	go func() {
		for {
			conn, err := tln.Accept()
			if err != nil {
				return
			}
			_ = conn.(*tls.Conn).HandshakeContext(t.Context())
			go func() {
				// Hold the connection open until the client closes it
				_, _ = conn.Read(make([]byte, 1))
				_ = conn.Close()
			}()
		}
	}()
	return tln
}

func TestDialLDAPSVerifiesCertificate(t *testing.T) {
	ln := tlsListener(t)
	conf := *Defaults
	conf.ServerURL = "ldaps://" + ln.Addr().String()
	conf.Timeout = 5

	al, err := New(&conf)
	require.NoError(t, err)
	assert.Equal(t, ConnectModeLDAPS, al.connectMode)
	_, err = al.dial()
	assert.Error(t, err, "self-signed certificate must be rejected")

	conf.Insecure = true
	al, err = New(&conf)
	require.NoError(t, err)
	conn, err := al.dial()
	require.NoError(t, err, "insecure skips verification")
	_ = conn.Close()
}

func TestNewValidatesServerURL(t *testing.T) {
	for _, u := range []string{"http://ldap.example.com:389", "ldap://ldap.example.com", "ldaps://ldap.example.com"} {
		conf := *Defaults
		conf.ServerURL = u
		_, err := New(&conf)
		assert.Error(t, err, u)
	}

	conf := *Defaults
	conf.ServerURL = "ldap://ldap.example.com:389/?startTLS=true"
	al, err := New(&conf)
	require.NoError(t, err)
	assert.Equal(t, ConnectModeStartTLS, al.connectMode)

	conf.ServerURL = "ldap://ldap.example.com:389"
	al, err = New(&conf)
	require.NoError(t, err)
	assert.Equal(t, ConnectModePlain, al.connectMode)

	conf.UserSearchFilter = "{{.Broken"
	_, err = New(&conf)
	assert.Error(t, err, "template errors are reported")
}

func TestEscapeFilterValue(t *testing.T) {
	assert.Equal(t, `a\2a\28\29\5c`, escapeFilterValue(`a*()\`))
	assert.Equal(t, []string{`\2a`, "b"}, escapeFilterValue([]string{"*", "b"}))
	assert.Equal(t, EntryMap{"cn": `x\29`, "dn": []string{`y\28`}}, escapeFilterValue(EntryMap{"cn": "x)", "dn": []string{"y("}}))
	assert.Equal(t, 42, escapeFilterValue(42), "other types are passed through")
}
