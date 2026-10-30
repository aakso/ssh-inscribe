package signapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

// The JWT library decodes claims before it checks the signature. When every
// request decoded into one shared claims object, a token with an invalid
// signature (rejected with 401) still wrote its payload into that object.
// These tests failed against that object: a forged token planted extensions
// and critical options into the next certificate, a logged-in user racing
// forged tokens received principals they were never granted, and a pending
// login could be completed the same way.

// forgedToken builds a token with the given auth context and a signature that
// does not verify.
func forgedToken(t *testing.T, actx map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	hdr, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	require.NoError(t, err)
	body, err := json.Marshal(map[string]any{
		"AuthContext": actx,
		"exp":         time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return enc(hdr) + "." + enc(body) + "." + enc([]byte("invalid signature"))
}

func signWith(t *testing.T, e *echo.Echo, token string) (int, *ssh.Certificate) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/sign", bytes.NewBuffer(testUserPublic))
	req.Header.Set("X-Auth", "Bearer "+token)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	if err != nil {
		return rec.Code, nil
	}
	cert, _ := k.(*ssh.Certificate)
	return rec.Code, cert
}

func signedToken(t *testing.T, sa *SignAPI, actx *auth.AuthContext) string {
	t.Helper()
	ss, err := sa.makeToken(actx).SignedString(sa.tkey)
	require.NoError(t, err)
	return ss
}

// A rejected forged token must not change what a later, valid login receives.
func TestForgedTokenDoesNotAffectLaterRequests(t *testing.T) {
	withAPI(t, func(e *echo.Echo, sa *SignAPI) {
		require.NoError(t, sa.signer.AddSigningKey(testCaPrivatePem, nil, ""))

		code, _ := signWith(t, e, forgedToken(t, map[string]any{
			"Status":          auth.StatusCompleted,
			"Principals":      []string{"root"},
			"Extensions":      map[string]string{"permit-port-forwarding": "", "permit-agent-forwarding": ""},
			"CriticalOptions": map[string]string{"force-command": "/usr/bin/injected"},
		}))
		assert.Equal(t, http.StatusUnauthorized, code)

		_, cert := signWith(t, e, signedToken(t, sa, &auth.AuthContext{
			Status:          auth.StatusCompleted,
			SubjectName:     "alice",
			Principals:      []string{"alice"},
			Extensions:      map[string]string{"permit-pty": ""},
			CriticalOptions: map[string]string{},
			AuthMeta:        map[string]any{auth.MetaAuditID: "audit-alice"},
		}))
		require.NotNil(t, cert)
		assert.Equal(t, []string{"alice"}, cert.ValidPrincipals)
		assert.Equal(t, map[string]string{"permit-pty": ""}, cert.Extensions)
		assert.Empty(t, cert.CriticalOptions)
		assert.NotContains(t, cert.KeyId, "root")
	})
}

// A logged-in user sending sign requests while forged tokens are in flight
// must only ever receive their own principals.
func TestForgedTokensDoNotChangeConcurrentCertificates(t *testing.T) {
	withAPI(t, func(e *echo.Echo, sa *SignAPI) {
		require.NoError(t, sa.signer.AddSigningKey(testCaPrivatePem, nil, ""))
		legit := signedToken(t, sa, &auth.AuthContext{
			Status:      auth.StatusCompleted,
			SubjectName: "mallory",
			Principals:  []string{"mallory"},
			AuthMeta:    map[string]any{auth.MetaAuditID: "audit-mallory"},
		})
		forged := forgedToken(t, map[string]any{
			"Status":     auth.StatusCompleted,
			"Principals": []string{"root"},
		})

		var issued, rooted atomic.Int64
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for range 4 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						signWith(t, e, forged)
					}
				}
			})
		}
		for range 200 {
			_, cert := signWith(t, e, legit)
			if cert == nil {
				continue
			}
			issued.Add(1)
			for _, p := range cert.ValidPrincipals {
				if p == "root" {
					rooted.Add(1)
				}
			}
		}
		close(stop)
		wg.Wait()

		assert.Equal(t, int64(200), issued.Load())
		assert.Zero(t, rooted.Load())
	})
}

// A pending token is handed out before any credentials (federated login).
// Forged tokens in flight must not turn it into a completed login.
func TestForgedTokensDoNotCompletePendingLogin(t *testing.T) {
	withAPI(t, func(e *echo.Echo, sa *SignAPI) {
		require.NoError(t, sa.signer.AddSigningKey(testCaPrivatePem, nil, ""))
		pending := signedToken(t, sa, &auth.AuthContext{Status: auth.StatusPending})
		forged := forgedToken(t, map[string]any{
			"Status":     auth.StatusCompleted,
			"Principals": []string{"root"},
		})

		var issued atomic.Int64
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for range 4 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
						signWith(t, e, forged)
					}
				}
			})
		}
		for range 100 {
			code, cert := signWith(t, e, pending)
			if cert != nil || code == http.StatusOK {
				issued.Add(1)
			}
		}
		close(stop)
		wg.Wait()
		assert.Zero(t, issued.Load(), "a pending login must never receive a certificate")
	})
}
