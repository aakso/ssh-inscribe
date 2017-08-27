package authmock

import (
	"bytes"

	"github.com/aakso/ssh-inscribe/pkg/auth"
)

type AuthMock struct {
	User         string
	Secret       []byte
	AuthName     string
	AuthRealm    string
	AuthContext  auth.AuthContext
	ReturnStatus int
}

func (am *AuthMock) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	meta := map[string]interface{}{}
	for k, v := range am.AuthContext.AuthMeta {
		meta[k] = v
	}
	for k, v := range creds.Meta {
		meta[k] = v
	}
	if creds.UserIdentifier == am.User && bytes.Equal(creds.Secret, am.Secret) {
		ctx := am.AuthContext
		ctx.Status = am.ReturnStatus
		ctx.Parent = pctx
		ctx.Authenticator = am.Name()
		ctx.SubjectName = am.User
		ctx.AuthMeta = meta
		return &ctx, true
	}
	return nil, false
}

func (am *AuthMock) Type() string {
	return "authmock"
}

func (am *AuthMock) Name() string {
	return am.AuthName
}

func (am *AuthMock) Realm() string {
	return am.AuthRealm
}

func (am *AuthMock) CredentialType() string {
	return auth.CredentialUserPassword
}
