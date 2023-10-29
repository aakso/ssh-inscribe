package authmock

import (
	"bytes"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

type AuthMock struct {
	User        string
	Secret      []byte
	AuthName    string
	AuthRealm   string
	AuthContext auth.AuthContext
}

func (am *AuthMock) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	if creds.UserIdentifier == am.User && bytes.Equal(creds.Secret, am.Secret) {
		ctx := am.AuthContext
		ctx.Status = auth.StatusCompleted
		ctx.Parent = pctx
		ctx.Authenticator = am.Name()
		ctx.SubjectName = am.User
		ctx.AuthMeta = creds.Meta
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
