package signapi

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/gobwas/glob"
	"github.com/golang-jwt/jwt/v5"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/keysigner"
	"github.com/aakso/ssh-inscribe/internal/util"
)

const (
	TokenLifeSecs = 120
)

type AuthenticatorListEntry struct {
	Authenticator auth.Authenticator
	Default       bool
}

type SignAPI struct {
	auth            map[string]auth.Authenticator
	authList        []AuthenticatorListEntry
	signer          *keysigner.KeySignerService
	tkey            []byte
	defaultCertLife time.Duration
	maxCertLife     time.Duration
	caChallengeLife time.Duration
	caChallengeKey  crypto.Signer
	caAdmins        []glob.Glob
}

func New(
	authList []AuthenticatorListEntry,
	signer *keysigner.KeySignerService,
	tkey []byte,
	defaultlife time.Duration,
	maxlife time.Duration,
	caChallengeLife time.Duration,
) *SignAPI {
	authMap := map[string]auth.Authenticator{}
	for _, v := range authList {
		authMap[v.Authenticator.Name()] = v.Authenticator
	}

	caChallengeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err.Error())
	}

	return &SignAPI{
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

// RestrictCAUpload limits CA key uploads to logins with a principal that
// matches one of the glob patterns. Without patterns any completed login may
// upload a key while none is loaded.
func (sa *SignAPI) RestrictCAUpload(patterns []string) error {
	globs := make([]glob.Glob, 0, len(patterns))
	for _, p := range patterns {
		g, err := glob.Compile(p)
		if err != nil {
			return fmt.Errorf("cannot compile CA admin principal %q: %w", p, err)
		}
		globs = append(globs, g)
	}
	sa.caAdmins = globs
	return nil
}

// isCAAdmin returns the principal that permits actx to upload the CA key.
func (sa *SignAPI) isCAAdmin(actx *auth.AuthContext) (string, bool) {
	if len(sa.caAdmins) == 0 {
		return "", true
	}
	principals, _ := auth.SplitUnsafePrincipals(actx.GetPrincipals())
	for _, p := range principals {
		for _, g := range sa.caAdmins {
			if g.Match(p) {
				return p, true
			}
		}
	}
	return "", false
}

type SignClaim struct {
	AuthContext *auth.AuthContext
	jwt.RegisteredClaims
}

func (sa *SignAPI) makeToken(actx *auth.AuthContext) *jwt.Token {
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
