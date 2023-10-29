package all

import (
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authfile"
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authldap"
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authoidc"
)
