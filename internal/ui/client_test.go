//go:build !windows

package ui

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/auth/backend/authmock"
	"github.com/aakso/ssh-inscribe/internal/globals"
	"github.com/aakso/ssh-inscribe/internal/keysigner"
	"github.com/aakso/ssh-inscribe/internal/server/signapi"
	"github.com/aakso/ssh-inscribe/internal/util"
)

const (
	testUser     = "alice"
	testPassword = "secret"
)

type testEnv struct {
	srv    *httptest.Server
	signer *keysigner.KeySignerService
	caPEM  []byte
	caPub  ssh.PublicKey
}

func newCAKey(t *testing.T) ([]byte, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	block, err := ssh.MarshalPrivateKey(priv, "test ca")
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(block), sshPub
}

// startServer runs the signing API with a mock authenticator over TLS. The
// CA key is loaded unless withoutCA is set.
func startServer(t *testing.T, withoutCA bool) *testEnv {
	t.Helper()
	signer := keysigner.New(filepath.Join(t.TempDir(), "agent.sock"), "")
	t.Cleanup(func() {
		signer.Close()
		signer.KillAgent()
	})
	require.Eventually(t, signer.AgentPing, 10*time.Second, 50*time.Millisecond, "ssh-agent did not start")

	env := &testEnv{signer: signer}
	env.caPEM, env.caPub = newCAKey(t)
	if !withoutCA {
		require.NoError(t, signer.AddSigningKey(env.caPEM, nil, ""))
	}

	am := &authmock.AuthMock{
		User:      testUser,
		Secret:    []byte(testPassword),
		AuthName:  "mock",
		AuthRealm: "test realm",
		AuthContext: auth.AuthContext{
			Principals: []string{testUser, "admins"},
			Extensions: map[string]string{"permit-pty": ""},
		},
	}
	sa := signapi.New(
		[]signapi.AuthenticatorListEntry{{Authenticator: am, Default: true}},
		signer, []byte("0123456789abcdef0123456789abcdef"),
		time.Hour, 24*time.Hour, time.Minute,
	)
	e := echo.New()
	e.GET("/version", func(c echo.Context) error { return c.String(http.StatusOK, globals.Version().String()) })
	sa.RegisterRoutes(e.Group("/v1"))
	env.srv = httptest.NewTLSServer(e)
	t.Cleanup(env.srv.Close)
	return env
}

// credentials answers prompts and counts them.
type credentials struct {
	password string
	prompts  []string
}

func (cr *credentials) input(_, _, credentialType, _ string) ([]byte, error) {
	cr.prompts = append(cr.prompts, credentialType)
	switch credentialType {
	case CredentialTypeUser:
		return []byte(testUser), nil
	case CredentialTypePassword:
		return []byte(cr.password), nil
	}
	return nil, nil
}

func (env *testEnv) client(t *testing.T, cr *credentials, mod func(*Config)) *Client {
	t.Helper()
	conf := &Config{
		URL:                 env.srv.URL,
		Insecure:            true,
		Timeout:             10 * time.Second,
		GenerateKeypair:     true,
		GenerateKeypairType: "ed25519",
		Quiet:               true,
	}
	if mod != nil {
		mod(conf)
	}
	c := &Client{Config: conf, credentialInput: cr.input}
	t.Cleanup(c.Close)
	return c
}

func (env *testEnv) assertSignedByCA(t *testing.T, cert *ssh.Certificate) {
	t.Helper()
	assert.Equal(t, env.caPub.Marshal(), cert.SignatureKey.Marshal())
	assert.True(t, shallowCertChecker(cert, env.caPub))
}

func TestLogin(t *testing.T) {
	env := startServer(t, false)
	cr := &credentials{password: testPassword}
	c := env.client(t, cr, nil)

	require.NoError(t, c.Login())
	require.Len(t, c.userCerts, 1)
	cert := c.userCerts[0]
	env.assertSignedByCA(t, cert)
	assert.Equal(t, []string{testUser, "admins"}, cert.ValidPrincipals)
	assert.Contains(t, cert.Extensions, "permit-pty")
	assert.Contains(t, cert.KeyId, `subject="alice"`)
	assert.Equal(t, ssh.KeyAlgoED25519, cert.Key.Type())
	assert.Equal(t, []string{CredentialTypeUser, CredentialTypePassword}, cr.prompts)
}

func TestLoginRetriesAfterWrongPassword(t *testing.T) {
	env := startServer(t, false)
	attempts := 0
	c := env.client(t, &credentials{}, nil)
	c.credentialInput = func(_, _, credentialType, _ string) ([]byte, error) {
		if credentialType == CredentialTypeUser {
			return []byte(testUser), nil
		}
		attempts++
		if attempts == 1 {
			return []byte("wrong"), nil
		}
		return []byte(testPassword), nil
	}
	require.NoError(t, c.Login())
	assert.Equal(t, 2, attempts)
	assert.Len(t, c.userCerts, 1)
}

func TestLoginPrincipalFilters(t *testing.T) {
	env := startServer(t, false)

	c := env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.IncludePrincipals = "adm*" })
	require.NoError(t, c.Login())
	assert.Equal(t, []string{"admins"}, c.userCerts[0].ValidPrincipals)

	c = env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.ExcludePrincipals = "adm*" })
	require.NoError(t, c.Login())
	assert.Equal(t, []string{testUser}, c.userCerts[0].ValidPrincipals)

	c = env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.IncludePrincipals = "nomatch" })
	err := c.Login()
	require.Error(t, err, "a certificate without principals must not be issued")
	assert.Contains(t, err.Error(), "403")
}

func TestLoginCertLifetime(t *testing.T) {
	env := startServer(t, false)
	c := env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.CertLifetime = 10 * time.Minute })
	require.NoError(t, c.Login())
	validFor := time.Until(util.CertTime(c.userCerts[0].ValidBefore))
	assert.InDelta(t, (10 * time.Minute).Seconds(), validFor.Seconds(), 5)

	c = env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.CertLifetime = 48 * time.Hour })
	assert.Error(t, c.Login(), "lifetime above the server maximum")
}

func TestLoginWritesFilesAndReusesValidCertificate(t *testing.T) {
	env := startServer(t, false)
	identity := filepath.Join(t.TempDir(), "id_test")
	// A pre-existing, too permissive file must end up private
	require.NoError(t, os.WriteFile(identity, []byte("old"), 0o644)) //nolint:gosec // permissive on purpose, see above

	cr := &credentials{password: testPassword}
	c := env.client(t, cr, func(conf *Config) {
		conf.IdentityFile = identity
		conf.WriteCert = true
	})
	require.NoError(t, c.Login())

	fi, err := os.Stat(identity)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	for _, f := range []string{identity + ".pub", identity + "-cert.pub"} {
		_, err := os.Stat(f)
		assert.NoError(t, err, f)
	}

	// Without --generate the existing key and its valid certificate are used
	// without logging in again.
	cr2 := &credentials{password: testPassword}
	c2 := env.client(t, cr2, func(conf *Config) {
		conf.IdentityFile = identity
		conf.GenerateKeypair = false
	})
	require.NoError(t, c2.Login())
	assert.Empty(t, cr2.prompts, "no login expected while the certificate is valid")
	require.Len(t, c2.userCerts, 1)
	env.assertSignedByCA(t, c2.userCerts[0])

	// --renew forces a new certificate for the same key
	cr3 := &credentials{password: testPassword}
	c3 := env.client(t, cr3, func(conf *Config) {
		conf.IdentityFile = identity
		conf.GenerateKeypair = false
		conf.AlwaysRenew = true
	})
	require.NoError(t, c3.Login())
	assert.NotEmpty(t, cr3.prompts)
	assert.Equal(t, c2.userCerts[0].Key.Marshal(), c3.userCerts[0].Key.Marshal())
}

// serveKeyring exposes an in-memory agent on a unix socket and points
// SSH_AUTH_SOCK at it.
func serveKeyring(t *testing.T) agent.Agent {
	t.Helper()
	keyring := agent.NewKeyring()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(keyring, conn)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
	return keyring
}

func TestLoginWithAgent(t *testing.T) {
	env := startServer(t, false)
	keyring := serveKeyring(t)

	cr := &credentials{password: testPassword}
	c := env.client(t, cr, func(conf *Config) { conf.UseAgent = true })
	require.NoError(t, c.Login())

	keys, err := keyring.List()
	require.NoError(t, err)
	var certs, plain int
	for _, k := range keys {
		assert.Equal(t, AgentComment, k.Comment)
		if strings.Contains(k.Format, "-cert-") {
			certs++
		} else {
			plain++
		}
	}
	assert.Equal(t, 1, certs)
	assert.Equal(t, 1, plain)

	// A valid certificate on the agent is reused
	cr2 := &credentials{password: testPassword}
	c2 := env.client(t, cr2, func(conf *Config) { conf.UseAgent = true })
	require.NoError(t, c2.Login())
	assert.Empty(t, cr2.prompts)

	// Logout removes the certificate and the key we added
	c3 := env.client(t, &credentials{}, func(conf *Config) { conf.UseAgent = true })
	require.NoError(t, c3.Logout())
	keys, err = keyring.List()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestCloseIsIdempotent(t *testing.T) {
	serveKeyring(t)
	hook := logtest.NewLocal(Log.Logger)
	t.Cleanup(hook.Reset)

	c := &Client{Config: &Config{}}
	require.NoError(t, c.connectAgent())
	c.Close()
	c.Close() // sshi exec closes explicitly and again when returning
	assert.Empty(t, hook.AllEntries(), "a second Close must not log errors")
}

func TestGetCAAndVersion(t *testing.T) {
	env := startServer(t, false)
	c := env.client(t, &credentials{}, nil)
	ca, err := c.GetCA()
	require.NoError(t, err)
	assert.Equal(t, env.caPub.Marshal(), ca.Marshal())

	ver, err := c.GetServerVersion()
	require.NoError(t, err)
	assert.Equal(t, globals.Version(), ver)

	authenticators, err := c.GetAuthenticators()
	require.NoError(t, err)
	require.Len(t, authenticators, 1)
	assert.Equal(t, "mock", authenticators[0].AuthenticatorName)
}

func TestLoginUnknownAuthEndpoint(t *testing.T) {
	env := startServer(t, false)
	c := env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.LoginAuthEndpoints = []string{"nope"} })
	assert.ErrorContains(t, c.Login(), "unknown auth endpoint")
}

func TestAddCA(t *testing.T) {
	env := startServer(t, true)
	caFile := filepath.Join(t.TempDir(), "ca")
	require.NoError(t, os.WriteFile(caFile, env.caPEM, 0o600))

	assert.False(t, env.signer.Ready())
	c := env.client(t, &credentials{password: testPassword}, func(conf *Config) { conf.CAKeyFile = caFile })
	require.NoError(t, c.AddCA())
	assert.True(t, env.signer.Ready())

	pub, err := env.signer.GetPublicKey()
	require.NoError(t, err)
	assert.Equal(t, env.caPub.Marshal(), pub.Marshal())
}

func TestInitRESTValidation(t *testing.T) {
	for name, conf := range map[string]*Config{
		"empty url":        {},
		"invalid url":      {URL: "http://[::1"},
		"negative retries": {URL: "https://example.com", Retries: -1},
	} {
		c := &Client{Config: conf}
		assert.Error(t, c.initREST(), name)
	}
}

func TestShallowCertChecker(t *testing.T) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	other, err := ssh.NewSignerFromKey(otherPriv)
	require.NoError(t, err)
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	userKey, err := ssh.NewPublicKey(userPub)
	require.NoError(t, err)

	now := util.CertTimestamp(time.Now())
	mk := func(after, before uint64, signer ssh.Signer) *ssh.Certificate {
		cert := &ssh.Certificate{Key: userKey, CertType: ssh.UserCert, ValidAfter: after, ValidBefore: before}
		require.NoError(t, cert.SignCert(rand.Reader, signer))
		return cert
	}
	assert.True(t, shallowCertChecker(mk(now-60, now+60, ca), ca.PublicKey()), "valid")
	assert.True(t, shallowCertChecker(mk(0, ssh.CertTimeInfinity, ca), ca.PublicKey()), "valid forever")
	assert.False(t, shallowCertChecker(mk(now-120, now-60, ca), ca.PublicKey()), "expired")
	assert.False(t, shallowCertChecker(mk(now+60, now+120, ca), ca.PublicKey()), "not yet valid")
	assert.False(t, shallowCertChecker(mk(now-60, now+60, other), ca.PublicKey()), "other CA")

	tampered := mk(now-60, now+60, ca)
	tampered.ValidPrincipals = []string{"root"}
	assert.False(t, shallowCertChecker(tampered, ca.PublicKey()), "signature no longer matches")
}

func TestPrintCertificate(t *testing.T) {
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca, err := ssh.NewSignerFromKey(caPriv)
	require.NoError(t, err)
	cert := &ssh.Certificate{
		Key: ca.PublicKey(), CertType: ssh.UserCert, KeyId: "kid",
		ValidPrincipals: []string{"p1", "p2"}, ValidBefore: ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{Extensions: map[string]string{"permit-pty": ""}},
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))

	c := &Client{ca: ca.PublicKey()}
	var out bytes.Buffer
	require.NoError(t, c.printCertificate(&out, cert))
	s := out.String()
	for _, want := range []string{"KeyId: kid", "Valid to: forever", "p1", "p2", "permit-pty", ssh.FingerprintSHA256(ca.PublicKey())} {
		assert.Contains(t, s, want)
	}
	assert.NotContains(t, s, "expires in")
}

func TestParsePrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	plain, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("pw"))
	require.NoError(t, err)

	prompts := 0
	c := &Client{credentialInput: func(_, _, _, _ string) ([]byte, error) {
		prompts++
		return []byte("pw"), nil
	}}
	_, err = c.parsePrivateKey(pem.EncodeToMemory(plain), "test")
	require.NoError(t, err)
	assert.Equal(t, 0, prompts)

	_, err = c.parsePrivateKey(pem.EncodeToMemory(encrypted), "test")
	require.NoError(t, err)
	assert.Equal(t, 1, prompts)

	c.credentialInput = func(_, _, _, _ string) ([]byte, error) {
		prompts++
		return []byte("wrong"), nil
	}
	prompts = 0
	_, err = c.parsePrivateKey(pem.EncodeToMemory(encrypted), "test")
	assert.Error(t, err)
	assert.Equal(t, 1, prompts, "only one attempt")

	_, err = c.parsePrivateKey([]byte("garbage"), "test")
	assert.Error(t, err)
}

func TestIsWebURL(t *testing.T) {
	for _, u := range []string{"https://idp.example.com/auth?x=1", "http://localhost:8080/cb"} {
		assert.True(t, isWebURL(u), u)
	}
	for _, u := range []string{"", "file:///etc/passwd", "javascript:alert(1)", "ms-settings:", "smb://host/share", "https:///nohost", "%"} {
		assert.False(t, isWebURL(u), u)
	}
}

func TestCapitalize(t *testing.T) {
	for in, want := range map[string]string{"password": "Password", "pin": "Pin", "": "", "älä": "Älä"} {
		assert.Equal(t, want, capitalize(in))
	}
}

func TestAskPass(t *testing.T) {
	dir := t.TempDir()
	write := func(name, script string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o700)) //nolint:gosec // test helper script must be executable
		return p
	}

	t.Setenv("SSH_ASKPASS", write("pw", `printf 'hunter2\n'`))
	assert.Equal(t, []byte("hunter2"), askPass("prompt"))

	t.Setenv("SSH_ASKPASS", write("empty", `exit 0`))
	assert.Empty(t, askPass("prompt"), "empty output must not panic")

	t.Setenv("SSH_ASKPASS", write("fail", `exit 1`))
	assert.Nil(t, askPass("prompt"))

	t.Setenv("SSH_ASKPASS", filepath.Join(dir, "missing"))
	assert.Nil(t, askPass("prompt"))
}
