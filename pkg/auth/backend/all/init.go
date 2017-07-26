package all

import (
	_ "github.com/aakso/ssh-inscribe/pkg/auth/backend/authfile"
	_ "github.com/aakso/ssh-inscribe/pkg/auth/backend/authldap"
	_ "github.com/aakso/ssh-inscribe/pkg/auth/backend/authoidc"
)
