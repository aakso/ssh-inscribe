package auth

const (
	CredentialUserPassword = "user_password"
	CredentialPin          = "pin"
	CredentialFederated    = "federated"

	MetaAuditID           = "audit_id"
	MetaFederationAuthURL = "federation_auth_url"
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
	Parent          *AuthContext
	Status          int
	SubjectName     string
	Principals      []string
	CriticalOptions map[string]string
	Extensions      map[string]string
	Authenticator   string
	Authorizer      string
	AuthMeta        map[string]interface{}
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
	if ac.Parent != nil {
		return append(ac.Principals, ac.Parent.GetPrincipals()...)
	}
	if ac.Status != StatusCompleted {
		return []string{}
	}
	return append(ac.Principals)
}
func (ac *AuthContext) GetCriticalOptions() map[string]string {
	r := map[string]string{}
	if ac.Parent != nil {
		for k, v := range ac.Parent.GetCriticalOptions() {
			r[k] = v
		}
	}
	if ac.Status != StatusCompleted {
		return map[string]string{}
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
	if ac.Status != StatusCompleted {
		return map[string]string{}
	}
	for k, v := range ac.Extensions {
		r[k] = v
	}
	return r
}
func (ac *AuthContext) GetAuthenticators() []string {
	if ac.Parent != nil {
		return append([]string{ac.Authenticator}, ac.Parent.GetAuthenticators()...)
	}
	return append([]string{ac.Authenticator})
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
		return append([]string{ac.Authorizer}, ac.Parent.GetAuthorizers()...)
	}
	return append([]string{ac.Authorizer})
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
