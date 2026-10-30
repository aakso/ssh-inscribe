package authoidc

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/util"
)

const (
	stateKey = "state"
	codeKey  = "code"

	subjectName = "subjectName"
	principal   = "principal"

	emailClaim         = "email"
	emailVerifiedClaim = "email_verified"
)

type entryState struct {
	claims map[string]any
	ts     time.Time

	// PKCE code verifier and OIDC nonce bound to this auth request
	verifier string
	nonce    string
}

type AuthOIDC struct {
	config      *Config
	log         *logrus.Entry
	tpls        *template.Template
	oauthConfig *oauth2.Config
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier

	sync.Mutex
	pendingRequests map[string]entryState
}

func (ao *AuthOIDC) authFlowTimeout() time.Duration {
	return time.Duration(ao.config.AuthFlowTimeout) * time.Second
}

func (ao *AuthOIDC) expired(e entryState, now time.Time) bool {
	return !e.ts.Add(ao.authFlowTimeout()).After(now)
}

// Save a new pending auth request. Expired requests are evicted first so
// that they do not count towards the limit.
func (ao *AuthOIDC) saveState(state string, entry entryState) error {
	ao.Lock()
	defer ao.Unlock()
	ao.evictExpiredLocked()
	if len(ao.pendingRequests) >= ao.config.MaxPendingAuthAttempts {
		return errors.New("maximum number of pending requests reached")
	}
	entry.ts = time.Now()
	ao.pendingRequests[state] = entry
	return nil
}

// Attach claims to a pending request. Only the first successful callback
// for a state is accepted.
func (ao *AuthOIDC) setClaims(state string, claims map[string]any) error {
	ao.Lock()
	defer ao.Unlock()
	e, ok := ao.pendingRequests[state]
	if !ok || ao.expired(e, time.Now()) {
		return errors.New("no matching state found")
	}
	if e.claims != nil {
		return errors.New("auth request already completed")
	}
	e.claims = claims
	ao.pendingRequests[state] = e
	return nil
}

// takeCompleted reports whether the request exists and, if its callback has
// completed, removes it and returns its claims. Taking and removing happen
// under one lock so that a request completes only once.
func (ao *AuthOIDC) takeCompleted(state string) (map[string]any, bool) {
	ao.Lock()
	defer ao.Unlock()
	e, ok := ao.pendingRequests[state]
	if !ok || ao.expired(e, time.Now()) {
		return nil, false
	}
	if e.claims != nil {
		delete(ao.pendingRequests, state)
	}
	return e.claims, true
}

// Return auth request if state key matches and the request hasn't expired
func (ao *AuthOIDC) getState(state string) (entryState, bool) {
	ao.Lock()
	defer ao.Unlock()
	if v, ok := ao.pendingRequests[state]; ok && !ao.expired(v, time.Now()) {
		return v, true
	}
	return entryState{}, false
}

func (ao *AuthOIDC) evictExpiredLocked() {
	now := time.Now()
	for k, v := range ao.pendingRequests {
		if ao.expired(v, now) {
			delete(ao.pendingRequests, k)
			ao.log.WithField("state", k).Info("evicted")
		}
	}
}

func (ao *AuthOIDC) startFlow(pctx *auth.AuthContext, meta map[string]any) (*auth.AuthContext, bool) {
	log := ao.log.WithField("action", "startFlow")
	if meta == nil {
		meta = map[string]any{}
	}
	// State will be used as a key to the cache containing the pending actx
	state := newRandomState()
	entry := entryState{
		verifier: oauth2.GenerateVerifier(),
		nonce:    newRandomState(),
	}
	log = log.WithField("state", state).WithField("audit_id", meta[auth.MetaAuditID])
	meta[stateKey] = state
	meta[auth.MetaFederationAuthURL] = ao.oauthConfig.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		oauth2.S256ChallengeOption(entry.verifier),
		oidc.Nonce(entry.nonce),
	)
	newctx := &auth.AuthContext{
		Status:        auth.StatusPending,
		Parent:        pctx,
		Authenticator: ao.Name(),
		AuthMeta:      meta,
	}
	if err := ao.saveState(state, entry); err != nil {
		log.WithError(err).Error("cannot save state")
		return nil, false
	}
	log.Info("waiting for auth callback")
	return newctx, true
}

func (ao *AuthOIDC) completeFlow(pctx *auth.AuthContext) (*auth.AuthContext, bool) {
	log := ao.log.WithField("action", "completeFlow")
	state := pctx.GetMetaString(stateKey)
	auditID := pctx.GetMetaString(auth.MetaAuditID)
	log = log.WithField("audit_id", auditID).
		WithField("state", state)
	// Check whether this is a started authorization
	if claims, ok := ao.takeCompleted(state); ok {
		if claims != nil {
			if err := ao.fillAuthContext(pctx, claims); err != nil {
				log.WithError(err).Warn("authentication rejected")
				return nil, false
			}
			log.Info("completed authentication")
			return pctx, true
		}
		log.Info("auth flow is incomplete")
		return pctx, true
	}
	log.Warning("unknown pending auth request")
	return nil, false
}

func (ao *AuthOIDC) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	if creds == nil {
		return nil, false
	}
	if pctx == nil {
		ao.log.Debug("no actx, start new flow")
		return ao.startFlow(nil, creds.Meta)
	}

	if pctx.Authenticator == ao.Name() {
		ao.log.Debug("completing flow")
		return ao.completeFlow(pctx)
	}

	ao.log.Debug("mfa, starting new flow")
	return ao.startFlow(pctx, creds.Meta)
}

func (ao *AuthOIDC) Type() string {
	return Type
}

func (ao *AuthOIDC) Name() string {
	return ao.config.Name
}

func (ao *AuthOIDC) Realm() string {
	return ao.config.Realm
}

func (ao *AuthOIDC) CredentialType() string {
	return auth.CredentialFederated
}

func (ao *AuthOIDC) FederationCallback(data any) error {
	log := ao.log.WithField("action", "callback")
	resp, ok := data.(url.Values)
	if !ok {
		log.Info("decoding error")
		return errors.New("decoding error")
	}
	state := resp.Get(stateKey)
	if state == "" {
		log.Info("no state")
		return errors.New("no state")
	}
	log = log.WithField("state", state)
	if idpErr := resp.Get("error"); idpErr != "" {
		log.WithField("error", idpErr).WithField("error_description", resp.Get("error_description")).
			Info("identity provider returned an error")
		return fmt.Errorf("identity provider returned an error: %s", idpErr)
	}
	code := resp.Get(codeKey)
	if code == "" {
		log.Info("no auth code")
		return errors.New("no auth code")
	}
	entry, ok := ao.getState(state)
	if !ok {
		log.Info("unknown state")
		return errors.New("no matching state found")
	}
	if entry.claims != nil {
		log.Warn("callback for an already completed auth request")
		return errors.New("auth request already completed")
	}

	tctx, cancel := context.WithTimeout(context.Background(), time.Duration(ao.config.Timeout)*time.Second)
	defer cancel()
	log.Debug("exchanging the code for a token")
	token, err := ao.oauthConfig.Exchange(tctx, code, oauth2.VerifierOption(entry.verifier))
	if err != nil {
		log.WithError(err).Error("cannot exchange auth code")
		return fmt.Errorf("cannot exchange auth code: %w", err)
	}
	log.Debug("validating token")
	claims, err := ao.validateToken(token, entry.nonce)
	if err != nil {
		log.WithError(err).Error("token validation failed")
		return fmt.Errorf("cannot validate token: %w", err)
	}
	if err := ao.setClaims(state, claims); err != nil {
		return err
	}
	log.Info("callback succeeded")
	return nil
}

func (ao *AuthOIDC) fillAuthContext(actx *auth.AuthContext, claims map[string]any) error {
	if err := ao.checkEmailVerified(claims); err != nil {
		return err
	}
	// Map user defined fields and run them thru the template
	actx.SubjectName = ao.renderTpl(subjectName, selectString(claims, ao.config.ValueMappings.SubjectNameField))
	for _, v := range selectStringSlice(claims, ao.config.ValueMappings.PrincipalsField) {
		if p := ao.renderTpl(principal, v); p != "" {
			actx.Principals = append(actx.Principals, p)
		}
	}
	// Fall back to single principal in case the token field is not a string slice
	if actx.Principals == nil {
		if s := selectString(claims, ao.config.ValueMappings.PrincipalsField); s != "" {
			if p := ao.renderTpl(principal, s); p != "" {
				actx.Principals = append(actx.Principals, p)
			}
		}
	}
	// Principals come from the identity provider; drop the ones sshd could
	// interpret as several principals.
	filtered := actx.Principals[:0]
	for _, p := range actx.Principals {
		if auth.UnsafePrincipal(p) {
			ao.log.WithField("principal", p).Warn("dropping unsafe principal")
			continue
		}
		filtered = append(filtered, p)
	}
	actx.Principals = filtered
	// From configuration
	actx.Principals = append(actx.Principals, ao.config.Principals...)
	actx.CriticalOptions = ao.config.CriticalOptions
	actx.Extensions = ao.config.Extensions

	actx.Status = auth.StatusCompleted
	return nil
}

// The email claim is only trustworthy if the provider has verified it.
// Some providers let users set an arbitrary address.
func (ao *AuthOIDC) checkEmailVerified(claims map[string]any) error {
	if !ao.config.RequireVerifiedEmail {
		return nil
	}
	vm := ao.config.ValueMappings
	if vm.PrincipalsField != emailClaim && vm.SubjectNameField != emailClaim {
		return nil
	}
	if verified, _ := claims[emailVerifiedClaim].(bool); !verified {
		return fmt.Errorf("%s claim is used but %s is not true", emailClaim, emailVerifiedClaim)
	}
	return nil
}

// Extract idtoken and fill auth context
func (ao *AuthOIDC) validateToken(token *oauth2.Token, nonce string) (map[string]any, error) {
	log := ao.log.WithField("action", "validateToken")
	jwtToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("%s: no id_token found", ao.Name())
	}
	tctx, cancel := context.WithTimeout(context.Background(), time.Duration(ao.config.Timeout)*time.Second)
	defer cancel()
	IDToken, err := ao.verifier.Verify(tctx, jwtToken)
	if err != nil {
		return nil, fmt.Errorf("verify error: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(IDToken.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("verify error: nonce mismatch")
	}
	claims := map[string]any{}
	if err = IDToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("claims unmarshal error: %w", err)
	}
	log.WithField("claims", claims).Debug("got claims")

	return claims, nil
}

func (ao *AuthOIDC) renderTpl(name string, data any) string {
	buf := bytes.NewBuffer([]byte{})
	err := ao.tpls.ExecuteTemplate(buf, name, data)
	if err != nil {
		ao.log.WithError(err).Errorf("template render error: %s", name)
	}
	return buf.String()
}

func selectStringSlice(m map[string]any, k string) []string {
	var r []string
	if v, ok := m[k]; ok {
		if slice, ok := v.([]any); ok {
			for _, e := range slice {
				r = append(r, fmt.Sprintf("%s", e))
			}
		}
	}
	return r
}

func selectString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func New(config *Config) (*AuthOIDC, error) {
	if config.ClientID == "" ||
		config.ClientSecret == "" ||
		config.ProviderURL == "" {
		return nil, fmt.Errorf("%s: required config items: clientId, clientSecret, authURL, tokenURL", config.Name)
	}
	log := Log.WithFields(logrus.Fields{
		"realm": config.Realm,
		"name":  config.Name,
	})

	var tplError error
	rootTpl := template.New("root")
	parseTpl := func(name, tpl string) {
		_, err := rootTpl.New(name).Parse(tpl)
		if err != nil {
			tplError = fmt.Errorf("cannot parse %s: %w", name, err)
		}
	}
	parseTpl(subjectName, config.ValueMappings.SubjectNameTemplate)
	parseTpl(principal, config.ValueMappings.PrincipalTemplate)
	if tplError != nil {
		return nil, tplError
	}

	provider, err := oidc.NewProvider(context.Background(), config.ProviderURL)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot instantiate auth provider: %w", config.Name, err)
	}
	log.WithFields(logrus.Fields{
		"auth_url":  provider.Endpoint().AuthURL,
		"token_url": provider.Endpoint().TokenURL,
	}).Info("auth provider discovered")

	r := &AuthOIDC{
		config:          config,
		tpls:            rootTpl,
		pendingRequests: map[string]entryState{},
		oauthConfig: &oauth2.Config{
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: config.ClientID,
		}),
		log: Log.WithFields(logrus.Fields{
			"realm": config.Realm,
			"name":  config.Name,
		}),
	}
	return r, nil
}

func newRandomState() string {
	state := util.RandB64(32)
	state = strings.ReplaceAll(state, "+", "-")
	state = strings.ReplaceAll(state, "/", "-")
	return state
}
