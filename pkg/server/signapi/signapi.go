package signapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/keysigner"
	"github.com/aakso/ssh-inscribe/pkg/util"
)

const (
	TokenLifeSecs = 120
)

type AuthenticatorListEntry struct {
	Authenticator auth.Authenticator
	Default       bool
}

type SignApi struct {
	auth            map[string]auth.Authenticator
	authList        []AuthenticatorListEntry
	defaultAuth     []string
	signer          *keysigner.KeySignerService
	tkey            []byte
	defaultCertLife time.Duration
	maxCertLife     time.Duration
	caChallengeLife time.Duration
	caChallengeKey  crypto.Signer
}

func New(
	authList []AuthenticatorListEntry,
	signer *keysigner.KeySignerService,
	tkey []byte,
	defaultlife time.Duration,
	maxlife time.Duration,
	caChallengeLife time.Duration,
) *SignApi {

	authMap := map[string]auth.Authenticator{}
	for _, v := range authList {
		authMap[v.Authenticator.Name()] = v.Authenticator
	}

	caChallengeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err.Error())
	}

	return &SignApi{
		auth:            authMap,
		authList:        authList,
		signer:          signer,
		tkey:            tkey,
		defaultCertLife: defaultlife,
		maxCertLife:     maxlife,
		caChallengeLife: caChallengeLife,
		caChallengeKey:  caChallengeKey,
	}
}

type SignClaim struct {
	AuthContext *auth.AuthContext
	jwt.RegisteredClaims
}

func (sa *SignApi) makeToken(actx *auth.AuthContext) *jwt.Token {
	claims := SignClaim{
		AuthContext: actx,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        util.RandB64(32), // Nonce
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * TokenLifeSecs)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
}
