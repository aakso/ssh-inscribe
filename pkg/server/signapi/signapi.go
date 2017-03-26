package signapi

import (
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/keysigner"
	"github.com/dgrijalva/jwt-go"
)

const (
	TokenLifeSecs = 120
)

type SignApi struct {
	auth            map[string]auth.Authenticator
	signer          *keysigner.KeySignerService
	tkey            []byte
	defaultCertLife time.Duration
	maxCertLife     time.Duration
}

func New(
	auth map[string]auth.Authenticator,
	signer *keysigner.KeySignerService,
	tkey []byte,
	defaultlife time.Duration,
	maxlife time.Duration,
) *SignApi {
	return &SignApi{
		auth:            auth,
		signer:          signer,
		tkey:            tkey,
		defaultCertLife: defaultlife,
		maxCertLife:     maxlife,
	}
}

type SignClaim struct {
	AuthContext *auth.AuthContext
	jwt.StandardClaims
}
