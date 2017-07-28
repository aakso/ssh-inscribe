package signapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/auth/backend/authmock"
	"github.com/aakso/ssh-inscribe/pkg/keysigner"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

var (
	testCaPublic     = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJrN8GEW7E0zsAUQN5xeaDSxo1KEUuIw4yMgLqeBKtyU80UCkJBhXF9K2boukTCUSkZinJOmCQBmDQxaMOT/k52NSMCQzGqzjBeiMxdflR75cgoAFgDL8fzkWfFWP6P/psVC/AeIwiPHHk4Kv4DYuDKgreB+8kMK8nHezoo6q4nxSaRO1zWa4kq17ce7ioMIrbZw0ALIB0rfM9+nahAGFbGrZxcUjtqAM7VGZWrVup9ALpDhnflmkyYTAKBVSGVnvQehqFXuK1xpaQ3avZHl085O2/wi4M8jeDpPpawXyoGr/UzCj+OWBsbIYh04MUqbrLWDWzJsE653VGGebo7jZd test-ca`)
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
		Principals:      []string{"fake1", "fake2", "fake3"},
		CriticalOptions: map[string]string{"test": "fake"},
	}

	authenticator *authmock.AuthMock = &authmock.AuthMock{
		User:        "test",
		Secret:      []byte("test"),
		AuthName:    "testauth",
		AuthRealm:   "testrealm",
		AuthContext: fakeAuthContext,
	}
	socketPath  string = path.Join(os.TempDir(), "signapitest")
	signapi     *SignApi
	e           *echo.Echo = echo.New()
	signingKey  []byte     = []byte("testkey")
	signedToken string
)

func TestMain(m *testing.M) {
	logging.SetLevel(logrus.DebugLevel)
	signer := keysigner.New(socketPath, "")
	auths := []AuthenticatorListEntry{
		AuthenticatorListEntry{
			Authenticator: authenticator,
			Default:       false,
		},
	}
	signapi = New(auths, signer, signingKey, 1*time.Hour, 24*time.Hour)
	signapi.RegisterRoutes(e.Group("/v1"))
	// Give keysigner some time to initialize
	time.Sleep(50 * time.Millisecond)
	ret := m.Run()
	signer.Close()
	signer.KillAgent()
	os.Exit(ret)
}

func TestDiscovery(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.GET, "/v1/auth", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)
}

func TestNotReady(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.GET, "/v1/ready", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusInternalServerError, rec.Code)
}

func TestLogin(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.POST, "/v1/auth/"+authenticator.Name(), nil)
	req.SetBasicAuth(authenticator.User, string(authenticator.Secret))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal("application/jwt", rec.Header().Get("Content-Type"))
	signedToken = rec.Body.String()
	token, err := jwt.ParseWithClaims(signedToken, &SignClaim{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if assert.NoError(err) {
		assert.True(token.Valid)
		claims, _ := token.Claims.(*SignClaim)
		assert.Equal(claims.AuthContext.GetSubjectName(), authenticator.User)
	}
}

func TestMultiFactorAuth(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.POST, "/v1/auth/"+authenticator.Name(), nil)
	req.SetBasicAuth(authenticator.User, string(authenticator.Secret))
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)
	assert.Equal("application/jwt", rec.Header().Get("Content-Type"))
	signedToken = rec.Body.String()
	token, err := jwt.ParseWithClaims(signedToken, &SignClaim{}, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if assert.NoError(err) {
		assert.True(token.Valid)
		claims, _ := token.Claims.(*SignClaim)
		assert.NotNil(claims.AuthContext.GetParent())
	}
}

func TestSignNoKey(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testUserPublic)
	req, _ := http.NewRequest(echo.POST, "/v1/sign", buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusInternalServerError, rec.Code)
}

func TestAddKey(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testCaPrivatePem)
	req, _ := http.NewRequest(echo.POST, "/v1/ca", buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusAccepted, rec.Code)
	assert.Empty(rec.Body.String())
}

func TestReady(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.GET, "/v1/ready", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusNoContent, rec.Code)
}

func TestGetKey(t *testing.T) {
	assert := assert.New(t)
	req, _ := http.NewRequest(echo.GET, "/v1/ca", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)
	assert.NotEmpty(rec.Body.String())
}

func TestSignCustomExpires(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testUserPublic)
	exp := time.Now().Add(5 * time.Second)
	u, _ := url.Parse("/v1/sign")
	q := u.Query()
	q.Set("expires", exp.Format(time.RFC3339))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(echo.POST, u.String(), buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)

	raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	if assert.NoError(err) {
		cert, _ := raw.(*ssh.Certificate)
		assert.NotNil(cert)
		assert.Equal(exp.Unix(), int64(cert.ValidBefore))
	}
}

func TestSignOverMaxLifetime(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testUserPublic)
	exp := time.Now().Add(25 * time.Hour)
	u, _ := url.Parse("/v1/sign")
	q := u.Query()
	q.Set("expires", exp.Format(time.RFC3339))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(echo.POST, u.String(), buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusBadRequest, rec.Code)
}

func TestSignPrincipalFilterInclude(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testUserPublic)
	u, _ := url.Parse("/v1/sign")
	q := u.Query()
	q.Set("include_principals", "fake2")
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(echo.POST, u.String(), buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)

	raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	if assert.NoError(err) {
		cert, _ := raw.(*ssh.Certificate)
		assert.NotNil(cert)
		assert.Contains(cert.ValidPrincipals, "fake2")
		assert.NotContains(cert.ValidPrincipals, "fake1")
	}
}

func TestSignPrincipalFilterExclude(t *testing.T) {
	assert := assert.New(t)
	buf := bytes.NewBuffer(testUserPublic)
	u, _ := url.Parse("/v1/sign")
	q := u.Query()
	q.Set("exclude_principals", "fake2")
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest(echo.POST, u.String(), buf)
	req.Header.Set("X-Auth", "Bearer "+signedToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(http.StatusOK, rec.Code)

	raw, _, _, _, err := ssh.ParseAuthorizedKey(rec.Body.Bytes())
	if assert.NoError(err) {
		cert, _ := raw.(*ssh.Certificate)
		assert.NotNil(cert)
		assert.Contains(cert.ValidPrincipals, "fake1")
		assert.NotContains(cert.ValidPrincipals, "fake2")
	}
}
