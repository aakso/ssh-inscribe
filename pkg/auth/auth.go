package auth

const (
	CredentialUserPassword = "user_password"
	CredentialPin          = "pin"
	CredentialFederated    = "federated"
	CredentialSSHPublicKey = "ssh_public_key"

	MetaAuditID           = "audit_id"
	MetaFederationAuthURL = "federation_auth_url"
	MetaChallenge         = "challenge"
)

type Authenticator interface {
	Authenticate(parentctx *AuthContext, creds *Credentials) (newctx *AuthContext, success bool)
	Type() string
	Name() string
	Realm() string
	CredentialType() string
}

// For OAuth2 type authenticators
type FederatedAuthenticator interface {
	Authenticator
	FederationCallback(data interface{}) error
}

type Authorizer interface {
	Authorize(parentctx *AuthContext) (newctx *AuthContext, success bool)
	Name() string
	Description() string
}

const (
	StatusPending int = iota
	StatusCompleted
)

type AuthContext struct {
	Parent           *AuthContext
	Status           int
	SubjectName      string
	Principals       []string
	RemovePrincipals []string
	CriticalOptions  map[string]string
	Extensions       map[string]string
	Authenticator    string
	Authorizer       string
	AuthMeta         map[string]interface{}
}

func (ac *AuthContext) GetParent() *AuthContext {
	return ac.Parent
}

func (ac *AuthContext) GetSubjectName() string {
	if ac.SubjectName == "" && ac.Parent != nil {
		return ac.Parent.GetSubjectName()
	}
	return ac.SubjectName
}

func (ac *AuthContext) GetPrincipals() []string {
	var r []string
	if ac.Parent != nil {
		r = append(r, ac.Parent.GetPrincipals()...)
	}

	r = append(r, ac.Principals...)

	if len(ac.RemovePrincipals) > 0 {
		m := map[string]bool{}
		for _, v := range ac.RemovePrincipals {
			m[v] = true
		}
		filtered := r[:0]
		for _, v := range r {
			if _, found := m[v]; !found {
				filtered = append(filtered, v)
			}
		}
		r = filtered
	}
	return r
}

func (ac *AuthContext) GetCriticalOptions() map[string]string {
	r := map[string]string{}
	if ac.Parent != nil {
		for k, v := range ac.Parent.GetCriticalOptions() {
			r[k] = v
		}
	}
	for k, v := range ac.CriticalOptions {
		r[k] = v
	}
	return r
}

func (ac *AuthContext) GetExtensions() map[string]string {
	r := map[string]string{}
	if ac.Parent != nil {
		for k, v := range ac.Parent.GetExtensions() {
			r[k] = v
		}
	}
	for k, v := range ac.Extensions {
		r[k] = v
	}
	return r
}

// The length of the auth context chain
func (ac *AuthContext) Len() int {
	l := 1
	if ac.Parent != nil {
		l += ac.Parent.Len()
	}
	return l
}

func (ac *AuthContext) GetAuthenticators() []string {
	if ac.Parent != nil {
		return filterEmptyValues(append([]string{ac.Authenticator}, ac.Parent.GetAuthenticators()...))
	}
	return filterEmptyValues(append([]string{ac.Authenticator}))
}

func (ac *AuthContext) GetAuthMeta() map[string]interface{} {
	r := map[string]interface{}{}
	if ac.Parent != nil {
		for k, v := range ac.Parent.GetAuthMeta() {
			r[k] = v
		}
	}
	for k, v := range ac.AuthMeta {
		r[k] = v
	}
	return r
}

func (ac *AuthContext) GetAuthorizers() []string {
	if ac.Parent != nil {
		return filterEmptyValues(append([]string{ac.Authorizer}, ac.Parent.GetAuthorizers()...))
	}
	return filterEmptyValues(append([]string{ac.Authorizer}))
}

// Verify the whole auth context chain
func (ac *AuthContext) IsValid() bool {
	var valid bool
	// Check the status is completed (for federated auth)
	valid = ac.Status == StatusCompleted

	// Check parent context
	if ac.Parent != nil {
		valid = valid && ac.Parent.IsValid()
	}

	return valid
}

func (ac *AuthContext) GetMetaString(k string) string {
	if v, ok := ac.AuthMeta[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return ""
	}
	return ""

}

type Credentials struct {
	UserIdentifier string `json:"userIdentifier"`
	Secret         []byte
	Meta           map[string]interface{}
}

func filterEmptyValues(sl []string) []string {
	r := sl[:0]
	for _, v := range sl {
		if v != "" {
			r = append(r, v)
		}
	}
	return r
}
