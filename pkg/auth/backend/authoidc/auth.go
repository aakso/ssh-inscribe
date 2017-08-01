package authoidc

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/util"
	"github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	stateKey = "state"
	codeKey  = "code"

	// Templates
	UserName    = "UserName"
	SubjectName = "SubjectName"
	Principals  = "Principals"
)

type entryState struct {
	token *oauth2.Token
	ts    time.Time
}

type AuthOIDC struct {
	config      *Config
	log         *logrus.Entry
	oauthConfig *oauth2.Config
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier

	sync.Mutex
	pendingRequests map[string]entryState
	nextEvict       *time.Timer
}

func (ao *AuthOIDC) authFlowTimeout() time.Duration {
	return time.Duration(ao.config.AuthFlowTimeout) * time.Second
}

// Save pending auth request with state key and schedule an evict task
func (ao *AuthOIDC) saveState(state string, token *oauth2.Token) error {
	if len(ao.pendingRequests) >= ao.config.MaxPendingAuthAttempts {
		return errors.New("maximum number of pending requests reached")
	}

	ao.pendingRequests[state] = entryState{token: token, ts: time.Now()}
	if ao.nextEvict != nil {
		ao.nextEvict.Reset(ao.authFlowTimeout())
	} else {
		ao.nextEvict = time.AfterFunc(ao.authFlowTimeout(), func() {
			ao.Lock()
			defer ao.Unlock()
			ao.evictStateEntries()
		})
	}
	return nil
}

// Return auth request if sate key matches and the request hasn't expired
func (ao *AuthOIDC) getState(state string) *entryState {
	if v, ok := ao.pendingRequests[state]; ok {
		if v.ts.Add(ao.authFlowTimeout()).After(time.Now()) {
			return &v
		}
	}
	return nil
}

// Evict expired auth requests
func (ao *AuthOIDC) evictStateEntries() {
	for k, v := range ao.pendingRequests {
		if v.ts.Add(ao.authFlowTimeout()).Before(time.Now()) {
			delete(ao.pendingRequests, k)
			ao.log.WithField("state", k).Info("evicted")
		}
	}
}

func (ao *AuthOIDC) startFlow(pctx *auth.AuthContext, meta map[string]interface{}) (*auth.AuthContext, bool) {
	log := ao.log.WithField("action", "startFlow")
	if meta == nil {
		meta = map[string]interface{}{}
	}
	// State will be used as a key to the cache containing the pending actx
	state := util.RandB64(32)
	log = log.WithField("state", state).WithField("audit_id", meta[auth.MetaAuditID])
	meta[stateKey] = state
	meta[auth.MetaFederationAuthURL] = ao.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	newctx := &auth.AuthContext{
		Status:        auth.StatusPending,
		Parent:        pctx,
		Authenticator: ao.Name(),
		AuthMeta:      meta,
	}
	if err := ao.saveState(state, nil); err != nil {
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
	if entry := ao.getState(state); entry != nil {
		if entry.token != nil {
			if err := ao.processToken(pctx, entry.token); err != nil {
				log.WithError(err).Error("cannot process token")
				return nil, false
			}
			delete(ao.pendingRequests, state)
			log.Info("completed authentication")
			return pctx, true
		} else {
			log.Info("auth flow is incomplete")
			return pctx, true
		}
	}
	log.Warning("unknown pending auth request")
	return nil, false
}

func (ao *AuthOIDC) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	if creds == nil {
		return nil, false
	}
	ao.Lock()
	defer ao.Unlock()
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

func (ao *AuthOIDC) FederationCallback(data interface{}) error {
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
	code := resp.Get(codeKey)
	if code == "" {
		log.Info("no auth code")
		return errors.New("no auth code")
	}
	ao.Lock()
	defer ao.Unlock()
	entry := ao.getState(state)
	if entry == nil {
		log.Info("unknown state")
		return errors.New("no matching state found")
	}

	tctx, cancel := context.WithTimeout(context.Background(), time.Duration(ao.config.Timeout)*time.Second)
	defer cancel()
	log.Debug("exchanging the code for a token")
	token, err := ao.oauthConfig.Exchange(tctx, code)
	if err != nil {
		log.WithError(err).Error("cannot exchange auth code")
		return errors.Wrap(err, "cannot exchange auth code")
	}
	if err := ao.saveState(state, token); err != nil {
		return err
	}
	log.Info("callback succeeded")
	return nil
}

// Extrack idtoken and fill auth context
func (ao *AuthOIDC) processToken(actx *auth.AuthContext, token *oauth2.Token) error {
	jwtToken, ok := token.Extra("id_token").(string)
	if !ok {
		return errors.Errorf("%s: no id_token found", ao.Name())
	}
	tctx, cancel := context.WithTimeout(context.Background(), time.Duration(ao.config.Timeout)*time.Second)
	defer cancel()
	IDToken, err := ao.verifier.Verify(tctx, jwtToken)
	if err != nil {
		return errors.Wrap(err, "verify error")
	}
	claims := map[string]interface{}{}
	IDToken.Claims(&claims)

	// Map user defined fields
	actx.SubjectName = selectString(claims, ao.config.ValueMappings.SubjectNameField)
	actx.Principals = selectStringSlice(claims, ao.config.ValueMappings.PrincipalsField)
	// Fall back to single principal in case the token field is not a string slice
	if actx.Principals == nil {
		if s := selectString(claims, ao.config.ValueMappings.PrincipalsField); s != "" {
			actx.Principals = append(actx.Principals, s)
		}
	}
	// From configuration
	actx.Principals = append(actx.Principals, ao.config.Principals...)
	actx.CriticalOptions = ao.config.CriticalOptions
	actx.Extensions = ao.config.Extensions

	actx.Status = auth.StatusCompleted

	return nil
}

func selectStringSlice(m map[string]interface{}, k string) []string {
	var r []string
	if v, ok := m[k]; ok {
		if slice, ok := v.([]interface{}); ok {
			for _, e := range slice {
				r = append(r, fmt.Sprintf("%s", e))
			}
		}
	}
	return r
}

func selectString(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func New(config *Config) (*AuthOIDC, error) {
	if config.ClientId == "" ||
		config.ClientSecret == "" ||
		config.ProviderURL == "" {

		return nil, errors.Errorf("%s: required config items: clientId, clientSecret, authURL, tokenURL", config.Name)
	}
	log := Log.WithFields(logrus.Fields{
		"realm": config.Realm,
		"name":  config.Name,
	})

	provider, err := oidc.NewProvider(context.Background(), config.ProviderURL)
	if err != nil {
		return nil, errors.Wrapf(err, "%s: cannot instantiate auth provider", config.Name)
	}
	log.WithFields(logrus.Fields{
		"auth_url":  provider.Endpoint().AuthURL,
		"token_url": provider.Endpoint().TokenURL,
	}).Info("auth provider discovered")

	r := &AuthOIDC{
		config:          config,
		pendingRequests: map[string]entryState{},
		oauthConfig: &oauth2.Config{
			RedirectURL:  config.RedirectURL,
			Endpoint:     provider.Endpoint(),
			ClientID:     config.ClientId,
			ClientSecret: config.ClientSecret,
			Scopes:       config.Scopes,
		},
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{
			ClientID: config.ClientId,
		}),
		log: Log.WithFields(logrus.Fields{
			"realm": config.Realm,
			"name":  config.Name,
		}),
	}
	return r, nil
}
