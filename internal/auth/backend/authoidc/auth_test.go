package authoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

var (
	privateKey *rsa.PrivateKey
	keys       *jose.JSONWebKeySet = &jose.JSONWebKeySet{}

	srvOIDC *httptest.Server
	srvJWKS *httptest.Server
)

func serverJWKS() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(keys)
	}))
}

func serverOIDCDiscover(jwksURI string) *httptest.Server {
	srv := httptest.NewUnstartedServer(nil)

	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
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
	conf.ClientID = "clientid"
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

type testIDClaims struct {
	Email         string   `json:"email,omitempty"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	Nonce         string   `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

// tokenServer emulates the token endpoint. It checks the PKCE verifier of
// the pending request identified by *state and issues an ID token built by
// mkClaims, which receives the nonce of that pending request.
func tokenServer(t *testing.T, ab *AuthOIDC, state *string, mkClaims func(nonce string) *testIDClaims) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry, ok := ab.getState(*state)
		if !assert.True(t, ok, "token request for unknown state") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !assert.Equal(t, entry.verifier, r.FormValue("code_verifier"), "PKCE verifier mismatch") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claims := mkClaims(entry.nonce)
		claims.RegisteredClaims = jwt.RegisteredClaims{
			Issuer:    srvOIDC.URL,
			Audience:  jwt.ClaimStrings([]string{ab.config.ClientID}),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		ss, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id_token":     ss,
			"token_type":   "Bearer",
			"access_token": "token",
			"expires_in":   3600,
		})
	}))
}

func TestAuthURLHasPKCEAndNonce(t *testing.T) {
	ab := getAuthenticator()
	newctx, ok := ab.Authenticate(nil, &auth.Credentials{})
	if !assert.True(t, ok) {
		return
	}
	u, err := url.Parse(newctx.GetMetaString(auth.MetaFederationAuthURL))
	if !assert.NoError(t, err) {
		return
	}
	q := u.Query()
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.NotEmpty(t, q.Get("nonce"))
	entry, _ := ab.getState(newctx.GetMetaString(stateKey))
	assert.Equal(t, entry.nonce, q.Get("nonce"))
}

func TestFederationCallback(t *testing.T) {
	var err error
	const (
		userName = "Test User"
		email    = "foo@bar.org"
	)
	groups := []string{"group1", "group2"}
	ab := getAuthenticator()
	var state string
	tsrv := tokenServer(t, ab, &state, func(nonce string) *testIDClaims {
		return &testIDClaims{Email: email, EmailVerified: new(true), Name: userName, Groups: groups, Nonce: nonce}
	})
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
	state = newctx.GetMetaString(stateKey)
	params.Set(stateKey, state)

	ab.oauthConfig.Endpoint.TokenURL = tsrv.URL
	err = ab.FederationCallback(params)
	if !assert.NoError(err) {
		return
	}
	err = ab.FederationCallback(params)
	assert.Error(err, "a second callback for the same state must be rejected")

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

// runFlow starts a flow, runs the callback against a token server issuing
// the given claims and tries to complete the flow.
func runFlow(t *testing.T, ab *AuthOIDC, mkClaims func(nonce string) *testIDClaims) (actx *auth.AuthContext, ok bool, callbackErr error) {
	t.Helper()
	var state string
	tsrv := tokenServer(t, ab, &state, mkClaims)
	defer tsrv.Close()
	ab.oauthConfig.Endpoint.TokenURL = tsrv.URL

	pending, started := ab.Authenticate(nil, &auth.Credentials{})
	if !assert.True(t, started) {
		return nil, false, nil
	}
	state = pending.GetMetaString(stateKey)
	callbackErr = ab.FederationCallback(url.Values{stateKey: {state}, codeKey: {"code"}})
	actx, ok = ab.Authenticate(pending, &auth.Credentials{})
	return actx, ok, callbackErr
}

func TestFederationCallbackNonceMismatch(t *testing.T) {
	ab := getAuthenticator()
	actx, _, err := runFlow(t, ab, func(string) *testIDClaims {
		return &testIDClaims{Name: "x", Groups: []string{"g"}, Nonce: "attacker supplied"}
	})
	assert.ErrorContains(t, err, "nonce")
	assert.Equal(t, auth.StatusPending, actx.Status, "flow must not complete")
}

func TestEmailPrincipalRequiresVerifiedEmail(t *testing.T) {
	cases := []struct {
		name     string
		verified *bool
		require  bool
		ok       bool
	}{
		{"verified", new(true), true, true},
		{"unverified", new(false), true, false},
		{"missing", nil, true, false},
		{"unverifiedNotRequired", new(false), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ab := getAuthenticator()
			ab.config.ValueMappings.PrincipalsField = "email"
			ab.config.RequireVerifiedEmail = tc.require
			actx, ok, err := runFlow(t, ab, func(nonce string) *testIDClaims {
				return &testIDClaims{Name: "x", Email: "victim@example.com", EmailVerified: tc.verified, Nonce: nonce}
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.ok, ok)
			if tc.ok && assert.NotNil(t, actx) {
				assert.Equal(t, []string{"victim@example.com"}, actx.Principals)
			} else {
				assert.Nil(t, actx)
			}
		})
	}
}

func TestPendingStateLimitEvictsExpired(t *testing.T) {
	ab := getAuthenticator()
	ab.config.MaxPendingAuthAttempts = 2
	ab.config.AuthFlowTimeout = 1
	assert.NoError(t, ab.saveState("a", entryState{}))
	assert.NoError(t, ab.saveState("b", entryState{}))
	assert.Error(t, ab.saveState("c", entryState{}), "limit reached")
	time.Sleep(1100 * time.Millisecond)
	assert.NoError(t, ab.saveState("c", entryState{}), "expired entries must not count towards the limit")
}

func TestStateConcurrencySafe(_ *testing.T) {
	ab := getAuthenticator()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 20 {
				st := newRandomState()
				_ = ab.saveState(st, entryState{})
				_, _ = ab.getState(st)
				_ = ab.setClaims(st, map[string]any{})
				_, _ = ab.takeCompleted(st)
			}
		})
	}
	wg.Wait()
}

func TestUnsafePrincipalsAreDropped(t *testing.T) {
	ab := getAuthenticator()
	actx, ok, err := runFlow(t, ab, func(nonce string) *testIDClaims {
		return &testIDClaims{Name: "x", Groups: []string{"devs", "evil,admins", "bad\nline"}, Nonce: nonce}
	})
	assert.NoError(t, err)
	if assert.True(t, ok) {
		assert.Equal(t, []string{"devs"}, actx.Principals)
	}
}

func TestFederationCallbackIdPError(t *testing.T) {
	ab := getAuthenticator()
	pending, ok := ab.Authenticate(nil, &auth.Credentials{})
	if !assert.True(t, ok) {
		return
	}
	state := pending.GetMetaString(stateKey)
	err := ab.FederationCallback(url.Values{
		stateKey:            {state},
		"error":             {"access_denied"},
		"error_description": {"user cancelled"},
	})
	assert.ErrorContains(t, err, "access_denied")

	actx, ok := ab.Authenticate(pending, &auth.Credentials{})
	assert.True(t, ok)
	assert.Equal(t, auth.StatusPending, actx.Status, "the flow stays pending")
}

func TestCompletionIsSingleUse(t *testing.T) {
	ab := getAuthenticator()
	var state string
	tsrv := tokenServer(t, ab, &state, func(nonce string) *testIDClaims {
		return &testIDClaims{Name: "x", Groups: []string{"g"}, Nonce: nonce}
	})
	defer tsrv.Close()
	ab.oauthConfig.Endpoint.TokenURL = tsrv.URL

	pending, ok := ab.Authenticate(nil, &auth.Credentials{})
	require.True(t, ok)
	state = pending.GetMetaString(stateKey)
	require.NoError(t, ab.FederationCallback(url.Values{stateKey: {state}, codeKey: {"code"}}))

	// Concurrent polls with the same pending token: only one may complete.
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		completed int
	)
	for range 20 {
		wg.Go(func() {
			pctx := *pending // each request decodes its own copy of the token
			actx, ok := ab.Authenticate(&pctx, &auth.Credentials{})
			if ok && actx.Status == auth.StatusCompleted {
				mu.Lock()
				completed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	assert.Equal(t, 1, completed)
}
