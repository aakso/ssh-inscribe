package signapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/ScaleFT/sshkeys"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/auth/backend/authmock"
	"github.com/aakso/ssh-inscribe/internal/keysigner"
	"github.com/aakso/ssh-inscribe/internal/logging"
	"github.com/aakso/ssh-inscribe/internal/util"
)

var (
	// testCaPublic     = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJrN8GEW7E0zsAUQN5xeaDSxo1KEUuIw4yMgLqeBKtyU80UCkJBhXF9K2boukTCUSkZinJOmCQBmDQxaMOT/k52NSMCQzGqzjBeiMxdflR75cgoAFgDL8fzkWfFWP6P/psVC/AeIwiPHHk4Kv4DYuDKgreB+8kMK8nHezoo6q4nxSaRO1zWa4kq17ce7ioMIrbZw0ALIB0rfM9+nahAGFbGrZxcUjtqAM7VGZWrVup9ALpDhnflmkyYTAKBVSGVnvQehqFXuK1xpaQ3avZHl085O2/wi4M8jeDpPpawXyoGr/UzCj+OWBsbIYh04MUqbrLWDWzJsE653VGGebo7jZd test-ca`)
	testCaPrivatePem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyazfBhFuxNM7AFEDecXmg0saNShFLiMOMjIC6ngSrclPNFAp
CQYVxfStm6LpEwlEpGYpyTpgkAZg0MWjDk/5OdjUjAkMxqs4wXojMXX5Ue+XIKAB
YAy/H85FnxVj+j/6bFQvwHiMIjxx5OCr+A2LgyoK3gfvJDCvJx3s6KOquJ8UmkTt
c1muJKte3Hu4qDCK22cNACyAdK3zPfp2oQBhWxq2cXFI7agDO1RmVq1bqfQC6Q4Z
35ZpMmEwCgVUhlZ70HoahV7itcaWkN2r2R5dPOTtv8IuDPI3g6T6WsF8qBq/1Mwo
/jlgbGyGIdODFKm6y1g1sybBOud1Rhnm6O42XQIDAQABAoIBAG3BCLaysgentQpd
DHku/F4jdyXKvqt3JHiowvF7Wx782X/syAhDKYJLwFdc918GwjZ96uu6O2bmMbYs
eKqHV2jl2fZDzpIoCIEyyQhX3dF7hFGbAmSVS0Yx6a3D5F8ChnSB9GLYt9rB7nHS
24PpSy2cqcFfrAOUAx5UqOOKfpRt91MieRix9PIcjyvrWgVOn8b3gpPRIg7sFK04
RpHv97Qq/8uYYk9P/+KGPgmgyun53RkC3AIlm8bcgMi/D2DZrAMPlU3lKQ3s1UDr
nJm30FW6R3d9d7/L0jZ0lqnBGzQuKxjqY66f25eAw15TtihSWx382TopCXWmakl0
I4rzCAECgYEA6Mp0PxSSbXegPCq6PzpFXPUm9v49LLVB/muLKAdSLinlTRe2lPqF
zLzDuvHXHyETNsEzbgUAtRaN9MgDJ6s254zDjoKN+aFi/5ZDa05WGINBri636qkH
+eCtbaedt+Iz/HBebDNdMmFJbktwwwoGIf06Sg5+NBRImPwrt7giQ10CgYEA3chA
VfnAc2SjbD9/T4kaakf8sMra8X+5y1NW6zAFU1VAAY5/neM9b71w3kU4ZRVMEVes
H64vriIrD3cCgSbMKwUN+6vN+aNTnjrsRJwI1rVl/+M7gfwzRERNOqCfdlrFgcfB
5iDz6GVJWBHwRtMCFpWzS0zm4qHkLue1KFInjwECgYEAmdJVV+1XCGB4j+lH4km1
1cPkOGcssyMedWhIrm2P/xMOAo/9xJl52hyNVTVCib5IPPES88r4ebBqoumbNBYt
lHluKvfXqrDagrqe2AQOXeo1d0xFmRiSPaoZzxBn5j7hTRhPPD4Agi7I38mXvDke
bk0uvAqxl+YjRnuyw5Y3hb0CgYBu6p+CYA2nqEUy9e6t0Futm6L8p/cnoEFDNsLZ
jIKdUp1YKfQY+nTXVV8FSokRxLzuT3J9xZeC9wOiEFroTIb/XN/JZfr1RoGjOMTA
62hgOQhyGSrBr2fUVHRrRbl6b5sndMe8V+6j40PzD8WjJhR9RxEML8Goxl5gNvGa
4Lt4AQKBgHEqMIRDxr9RYbXSlRZqtJRvlN173YbBAdLVg/VUz8jxqXBcQl2AA9Fm
D5sRPJP9cTEWfmrxeZAETGhWxQkQQU956NJdXnLVOCopi2J1rD/Y2waUvGoihSuX
BOKQEAfMgR02w/4NuPb3mX27mk74/MKvR4ixv2zK6ExBL4u4ICdS
-----END RSA PRIVATE KEY-----`)
	testUserPublic                   = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC32gyZOLC0RHDntCk+0T5pDNYYytfmP/Jzx+tpqNGEuCWnOV9PwBLdRPT2SNIzCq1GBQWYg63GZ4qWbuvSBvo904Y69q0RWugbcNjpclzkJGT0Bl50l/ppeuJ8wLVFnguCH92E2ja/8tiIPtetKGmFDdSTETIRshGUE6PnuPy2/1BL1ES55XfOGLcvzf/yDi+JeuwQqWi8YMxAIm8ug0yn4GPBPK/MNpnMG3AQmwmviQT6nC6Ky/B9VJk2418v++lAgKRXwyqUeaHd2jAj+5lQ72zc3mZjwFnwTZJWySaGtqxQea9l1wYOhZOEyV4+KOgfLoZ3ps+vmMLGSxmnGmAj user`)
	fakeAuthContext auth.AuthContext = auth.AuthContext{
		Principals:      genFakePrincipals(),
		CriticalOptions: map[string]string{"test": "fake"},
		AuthMeta:        map[string]interface{}{auth.MetaAuditID: "fake"},
	}

	authenticator *authmock.AuthMock = &authmock.AuthMock{
		User:        "test",
		Secret:      []byte("test"),
		AuthName:    "testauth",
		AuthRealm:   "testrealm",
		AuthContext: fakeAuthContext,
	}
	socketPath          string = path.Join(os.TempDir(), "signapitest")
	signingKey          []byte = []byte("testkey")
	caChallengeLifetime        = 3 * time.Second
)

// genNumPrincipals sets the number of principals to test. OpenSSH has SSHKEY_CERT_MAX_PRINCIPALS set to 256.
const genNumPrincipals = 257

func genFakePrincipals() []string {
	var principals []string
	for i := 0; i < genNumPrincipals; i++ {
		principals = append(principals, fmt.Sprintf("fake%d", i))
	}
	return principals
}

func TestMain(m *testing.M) {
	logging.SetLevel(logrus.DebugLevel)
	os.Exit(m.Run())
}

func withApi(fn func(e *echo.Echo, signapi *SignApi)) {
	signer := keysigner.New(socketPath, "")
	for i := 0; i < 3; i++ {
		if signer.AgentPing() {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !signer.AgentPing() {
		panic("ssh-agent not responding")
	}
	if err := signer.RemoveAllKeys(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "warning: cannot remove keys: %v\n", err)
	}
	auths := []AuthenticatorListEntry{
		AuthenticatorListEntry{
			Authenticator: authenticator,
			Default:       false,
		},
	}
	echo := echo.New()
	signapi := New(auths, signer, signingKey, 1*time.Hour, 24*time.Hour, caChallengeLifetime)
	signapi.RegisterRoutes(echo.Group("/v1"))
	// Give keysigner some time to initialize
	time.Sleep(50 * time.Millisecond)
	fn(echo, signapi)
	signer.Close()
	signer.KillAgent()
}

func TestDiscovery(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		req, _ := http.NewRequest(echo.GET, "/v1/auth", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestNotReady(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		req, _ := http.NewRequest(echo.GET, "/v1/ready", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestLogin(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		req, _ := http.NewRequest(echo.POST, "/v1/auth/"+authenticator.Name(), nil)
		req.SetBasicAuth(authenticator.User, string(authenticator.Secret))
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/jwt", rec.Header().Get("Content-Type"))
		signedToken := rec.Body.String()
		token, err := jwt.ParseWithClaims(signedToken, &SignClaim{}, func(token *jwt.Token) (interface{}, error) {
			return signingKey, nil
		})
		if assert.NoError(t, err) {
			assert.True(t, token.Valid)
			claims, _ := token.Claims.(*SignClaim)
			assert.Equal(t, claims.AuthContext.GetSubjectName(), authenticator.User)
		}

		t.Run("TestMultiFactorAuth", func(t *testing.T) {
			req, _ := http.NewRequest(echo.POST, "/v1/auth/"+authenticator.Name(), nil)
			req.SetBasicAuth(authenticator.User, string(authenticator.Secret))
			req.Header.Set("X-Auth", "Bearer "+signedToken)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "application/jwt", rec.Header().Get("Content-Type"))
			signedToken = rec.Body.String()
			token, err := jwt.ParseWithClaims(signedToken, &SignClaim{}, func(token *jwt.Token) (interface{}, error) {
				return signingKey, nil
			})
			if assert.NoError(t, err) {
				assert.True(t, token.Valid)
				claims, _ := token.Claims.(*SignClaim)
				assert.NotNil(t, claims.AuthContext.GetParent())
			}
		})
	})
}

func TestLoginLongAuthContext(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		actx := &auth.AuthContext{Status: auth.StatusCompleted}
		for i := 1; i <= MaxAuthContextChainLength; i++ {
			actx = &auth.AuthContext{Parent: actx, Status: auth.StatusCompleted}
		}
		token := signapi.makeToken(actx)
		ss, _ := token.SignedString(signapi.tkey)

		req, _ := http.NewRequest(echo.POST, "/v1/auth/"+authenticator.Name(), nil)
		req.SetBasicAuth(authenticator.User, string(authenticator.Secret))
		req.Header.Set("X-Auth", "Bearer "+ss)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		_, err := jwt.ParseWithClaims(rec.Body.String(), &SignClaim{}, func(token *jwt.Token) (interface{}, error) {
			return signingKey, nil
		})
		assert.Error(t, err, "we shouldn't have received a valid token")
	})
}

func TestAddCaKeyWithChallenge(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		actx := fakeAuthContext
		actx.Status = auth.StatusCompleted
		token := signapi.makeToken(&actx)
		ss, _ := token.SignedString(signapi.tkey)

		t.Run("TestAddUnencrypted", func(t *testing.T) {
			buf := bytes.NewBuffer(testCaPrivatePem)
			req, _ := http.NewRequest(echo.POST, "/v1/ca?init_challenge=true", buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.False(t, signapi.signer.Ready())
		})

		t.Run("TestInitiateChallenge", func(t *testing.T) {
			parsedKey, _ := sshkeys.ParseEncryptedRawPrivateKey(testCaPrivatePem, nil)
			passphrase := util.RandBytes(64)
			encryptedKeyPem, _ := sshkeys.Marshal(parsedKey, &sshkeys.MarshalOptions{
				Passphrase: passphrase,
				Format:     sshkeys.FormatClassicPEM,
			})
			encryptedKeyOpenSsh, _ := sshkeys.Marshal(parsedKey, &sshkeys.MarshalOptions{
				Passphrase: passphrase,
				Format:     sshkeys.FormatOpenSSHv1,
			})
			type args struct {
				name string
				key  []byte
			}
			tests := []args{
				{"Pem", encryptedKeyPem},
				{"Openssh", encryptedKeyOpenSsh},
			}
			for _, testArgs := range tests {
				t.Run("RespondWith"+testArgs.name, func(t *testing.T) {
					rec := httptest.NewRecorder()
					req, _ := http.NewRequest(echo.POST, "/v1/ca?init_challenge=true", bytes.NewBuffer(testArgs.key))
					req.Header.Set("X-Auth", "Bearer "+ss)
					e.ServeHTTP(rec, req)
					if !assert.Equal(t, http.StatusAccepted, rec.Code) {
						return
					}
					_ = signapi.signer.RemoveAllKeys()
					req, _ = http.NewRequest(echo.POST, "/v1/ca/response", rec.Body)
					req.Header.Set("X-Auth", "Bearer "+ss)
					req.SetBasicAuth("", string(passphrase))
					rec = httptest.NewRecorder()
					e.ServeHTTP(rec, req)
					assert.Equal(t, http.StatusOK, rec.Code)
					fmt.Println(rec.Body.String())
				})
			}
			t.Run("RespondWitExpired", func(t *testing.T) {
				_ = signapi.signer.RemoveAllKeys()
				rec := httptest.NewRecorder()
				req, _ := http.NewRequest(echo.POST, "/v1/ca?init_challenge=true", bytes.NewBuffer(encryptedKeyOpenSsh))
				req.Header.Set("X-Auth", "Bearer "+ss)
				e.ServeHTTP(rec, req)
				if !assert.Equal(t, http.StatusAccepted, rec.Code) {
					return
				}
				time.Sleep(caChallengeLifetime)
				req, _ = http.NewRequest(echo.POST, "/v1/ca/response", rec.Body)
				req.Header.Set("X-Auth", "Bearer "+ss)
				req.SetBasicAuth("", string(passphrase))
				rec = httptest.NewRecorder()
				e.ServeHTTP(rec, req)
				assert.Equal(t, http.StatusForbidden, rec.Code)
			})
		})
	})
}

func TestSigning(t *testing.T) {
	withApi(func(e *echo.Echo, signapi *SignApi) {
		actx := fakeAuthContext
		actx.Status = auth.StatusCompleted
		token := signapi.makeToken(&actx)
		ss, _ := token.SignedString(signapi.tkey)

		buf := bytes.NewBuffer(testUserPublic)
		req, _ := http.NewRequest(echo.POST, "/v1/sign", buf)
		req.Header.Set("X-Auth", "Bearer "+ss)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)

		buf = bytes.NewBuffer(testCaPrivatePem)
		req, _ = http.NewRequest(echo.POST, "/v1/ca", buf)
		req.Header.Set("X-Auth", "Bearer "+ss)
		rec = httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.Empty(t, rec.Body.String())

		t.Run("TestReady", func(t *testing.T) {
			req, _ := http.NewRequest(echo.GET, "/v1/ready", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusNoContent, rec.Code)
		})

		t.Run("TestGetKey", func(t *testing.T) {
			req, _ := http.NewRequest(echo.GET, "/v1/ca", nil)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.NotEmpty(t, rec.Body.String())
		})

		t.Run("TestSignSha256", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("signing_option", "rsa-sha2-256")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			if assert.NoError(t, err) {
				cert, _ := raw.(*ssh.Certificate)
				assert.NotNil(t, cert)
				assert.Equal(t, "rsa-sha2-256", cert.Signature.Format)
			}
		})

		t.Run("TestSignSha512", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("signing_option", "rsa-sha2-512")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			if assert.NoError(t, err) {
				cert, _ := raw.(*ssh.Certificate)
				assert.NotNil(t, cert)
				assert.Equal(t, "rsa-sha2-512", cert.Signature.Format)
			}
		})

		t.Run("TestSignUnknownOption", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("signing_option", "fake")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})

		t.Run("TestSignCustomExpires", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			exp := time.Now().Add(5 * time.Second)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("expires", exp.Format(time.RFC3339))
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			if assert.NoError(t, err) {
				cert, _ := raw.(*ssh.Certificate)
				assert.NotNil(t, cert)
				assert.Equal(t, exp.Unix(), int64(cert.ValidBefore))
			}
		})

		t.Run("TestSignPendingAuthContext", func(t *testing.T) {
			pendingActx := &auth.AuthContext{
				Parent: &auth.AuthContext{
					Status: auth.StatusPending,
				},
				Status: auth.StatusCompleted,
			}
			pendingToken := signapi.makeToken(pendingActx)
			pendingSignedString, _ := pendingToken.SignedString(signapi.tkey)

			u, _ := url.Parse("/v1/sign")
			req, _ := http.NewRequest(echo.POST, u.String(), nil)
			req.Header.Set("X-Auth", "Bearer "+pendingSignedString)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			_, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			assert.Error(t, err, "we shouldn't have received a certificate")
		})

		t.Run("TestSignOverMaxLifetime", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			exp := time.Now().Add(25 * time.Hour)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("expires", exp.Format(time.RFC3339))
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})

		t.Run("TestSignPrincipalFilterInclude", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("include_principals", "fake2")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			if assert.NoError(t, err) {
				cert, _ := raw.(*ssh.Certificate)
				assert.NotNil(t, cert)
				assert.Contains(t, cert.ValidPrincipals, "fake2")
				assert.NotContains(t, cert.ValidPrincipals, "fake1")
			}
		})

		t.Run("TestSignPrincipalFilterExclude", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("exclude_principals", "fake2")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
			if assert.NoError(t, err) {
				cert, _ := raw.(*ssh.Certificate)
				assert.NotNil(t, cert)
				assert.Contains(t, cert.ValidPrincipals, "fake1")
				assert.NotContains(t, cert.ValidPrincipals, "fake2")
			}
		})

		t.Run("TestSignWithMaxPrincipalsPerCertificate", func(t *testing.T) {
			buf := bytes.NewBuffer(testUserPublic)
			u, _ := url.Parse("/v1/sign")
			q := u.Query()
			q.Set("max_principals_per_certificate", "42")
			u.RawQuery = q.Encode()
			req, _ := http.NewRequest(echo.POST, u.String(), buf)
			req.Header.Set("X-Auth", "Bearer "+ss)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)

			rawCerts := rec.Body.Bytes()
			remainingPrincipals := genNumPrincipals
			for len(rawCerts) > 0 {
				var (
					pubKey ssh.PublicKey
					err    error
				)
				pubKey, _, _, rawCerts, err = ssh.ParseAuthorizedKey(rawCerts)
				if assert.NoError(t, err) {
					cert, _ := pubKey.(*ssh.Certificate)
					assert.NotNil(t, cert)
					remainingPrincipals -= len(cert.ValidPrincipals)
				}
			}
			assert.Zero(t, remainingPrincipals)
		})

		t.Run("TestSignWithInvalidMaxPrincipalsPerCertificate", func(t *testing.T) {
			cases := []struct {
				name string
				val  string
			}{
				{
					name: "notAnInteger",
					val:  "invalid",
				},
				{
					name: "tooLow",
					val:  "1",
				},
				{
					name: "negative",
					val:  "-1",
				},
			}
			for _, tt := range cases {
				t.Run(tt.name, func(t *testing.T) {
					buf := bytes.NewBuffer(testUserPublic)
					u, _ := url.Parse("/v1/sign")
					q := u.Query()
					q.Set("max_principals_per_certificate", tt.val)
					u.RawQuery = q.Encode()
					req, _ := http.NewRequest(echo.POST, u.String(), buf)
					req.Header.Set("X-Auth", "Bearer "+ss)
					rec := httptest.NewRecorder()
					e.ServeHTTP(rec, req)
					assert.Equal(t, http.StatusBadRequest, rec.Code)
				})
			}
		})
	})
}
