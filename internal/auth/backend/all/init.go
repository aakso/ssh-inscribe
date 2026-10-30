// Package all registers every authentication backend with the backend
// registry by importing it for its side effects.
package all

import (
	// Registers the authfile backend
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authfile"
	// Registers the authldap backend
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authldap"
	// Registers the authoidc backend
	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/authoidc"
)
