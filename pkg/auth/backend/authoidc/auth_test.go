package authoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"os"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

var (
	privateKey *rsa.PrivateKey
	keys       *jose.JSONWebKeySet = &jose.JSONWebKeySet{}

	srvOIDC *httptest.Server
	srvJWKS *httptest.Server
)

func serverJWKS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(keys)
	}))
}

func serverOIDCDiscover(jwksURI string) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)

	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"issuer":   srv.URL,
			"jwks_uri": jwksURI,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv.Start()
	return srv
}

func getAuthenticator() *AuthOIDC {
	conf := *Defaults
	conf.ClientId = "clientid"
	conf.ClientSecret = "clientsecret"
	conf.RedirectURL = "https://localhost:12900/some/path"
	conf.ProviderURL = srvOIDC.URL
	conf.ValueMappings.PrincipalsField = "groups"
	ab, err := New(&conf)
	if err != nil {
		panic(err)
	}
	return ab
}

func initServers() {
	srvJWKS = serverJWKS()
	srvOIDC = serverOIDCDiscover(srvJWKS.URL)
}

func cleanup() {
	srvJWKS.Close()
	srvOIDC.Close()
}

func initKeys() {
	var err error
	keys.Keys = []jose.JSONWebKey{}
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	keys.Keys = append(keys.Keys, jose.JSONWebKey{
		Key:   &privateKey.PublicKey,
		KeyID: "foo",
		Use:   "sig",
	})
}

func TestMain(m *testing.M) {
	initKeys()
	initServers()
	r := m.Run()
	cleanup()
	os.Exit(r)
}

func TestStartAuth(t *testing.T) {
	ab := getAuthenticator()
	assert := assert.New(t)
	newctx, ok := ab.Authenticate(nil, &auth.Credentials{})
	assert.True(ok)
	if assert.NotNil(newctx) {
		assert.NotNil(newctx.AuthMeta[auth.MetaFederationAuthURL])
		assert.NotNil(newctx.AuthMeta[stateKey])
	}
}

func TestIncompletedAuth(t *testing.T) {
	ab := getAuthenticator()
	assert := assert.New(t)
	newctx, _ := ab.Authenticate(nil, &auth.Credentials{})
	newctx, _ = ab.Authenticate(newctx, &auth.Credentials{})
	assert.Equal(newctx.Status, auth.StatusPending)
}

func TestChainedAuthCtx(t *testing.T) {
	ab := getAuthenticator()
	assert := assert.New(t)
	ctx := &auth.AuthContext{
		Authenticator: "some other",
	}
	newctx, ok := ab.Authenticate(ctx, &auth.Credentials{})
	assert.True(ok)
	if assert.NotNil(newctx) {
		assert.Equal(newctx.Authenticator, ab.Name())
		assert.Equal(newctx.Parent, ctx)
	}
}

func TestFederationCallback(t *testing.T) {
	var err error
	const (
		userName = "Test User"
		email    = "foo@bar.org"
	)
	groups := []string{"group1", "group2"}
	ab := getAuthenticator()
	tsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := &struct {
			Email         string   `json:"email"`
			EmailVerified bool     `json:"email_verified"`
			Name          string   `json:"name"`
			Groups        []string `json:"groups"`
			jwt.StandardClaims
		}{
			Email:         email,
			EmailVerified: true,
			Name:          userName,
			Groups:        groups,
			StandardClaims: jwt.StandardClaims{
				Issuer:    srvOIDC.URL,
				Audience:  ab.config.ClientId,
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
		}
		ss, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		t := map[string]interface{}{
			"id_token":     ss,
			"token_type":   "Bearer",
			"access_token": "token",
			"expires_in":   3600,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(t)
	}))
	defer tsrv.Close()
	assert := assert.New(t)
	pctx := &auth.AuthContext{
		Status:        auth.StatusCompleted,
		Authenticator: "some other",
	}
	newctx, ok := ab.Authenticate(pctx, &auth.Credentials{})
	assert.True(ok)
	if !assert.NotNil(newctx) {
		return
	}
	newctx, ok = ab.Authenticate(newctx, &auth.Credentials{})
	assert.True(ok)
	if !assert.NotNil(newctx) {
		return
	}

	params := url.Values{}

	// Test failure scenarios
	err = ab.FederationCallback(nil)
	assert.Error(err, "should error with nil params")
	err = ab.FederationCallback(params)
	assert.Error(err, "should error without state param")
	params.Set(stateKey, "invalid")
	err = ab.FederationCallback(params)
	assert.Error(err, "should error without code param")
	params.Set(codeKey, "the code")
	err = ab.FederationCallback(params)
	assert.Error(err, "should error with invalid state param")
	params.Set(stateKey, newctx.GetMetaString(stateKey))

	ab.oauthConfig.Endpoint.TokenURL = tsrv.URL
	err = ab.FederationCallback(params)
	if !assert.NoError(err) {
		return
	}

	newctx, ok = ab.Authenticate(newctx, &auth.Credentials{})
	assert.True(ok)
	if !assert.NotNil(newctx) {
		return
	}
	assert.Equal(auth.StatusCompleted, newctx.Status)
	assert.Equal(userName, newctx.SubjectName)
	assert.Equal(groups, newctx.Principals)
	assert.Equal(2, newctx.Len())

	newctx, ok = ab.Authenticate(newctx, &auth.Credentials{})
	assert.False(ok, "repeating completed flow should return auth failure")
	assert.Nil(newctx, "repeating completed flow should return auth failure")
}
