package signapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

func (sa *SignAPI) HandleAddKey(c echo.Context) error {
	var actx *auth.AuthContext
	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			actx = claims.AuthContext
		}
	}
	if actx == nil {
		return errors.New("no auth context")
	}
	if !actx.IsValid() {
		return echo.NewHTTPError(http.StatusBadRequest, "auth context is not valid")
	}
	auditID, _ := actx.GetAuthMeta()[auth.MetaAuditID].(string)
	log := Log.WithField("audit_id", auditID)

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		err = fmt.Errorf("cannot read private key: %w", err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Encrypted CA challenge
	if v, _ := strconv.ParseBool(c.QueryParam("init_challenge")); v {
		_, err := ssh.ParseRawPrivateKey(body)
		passphraseMissingError := &ssh.PassphraseMissingError{}
		if !errors.As(err, &passphraseMissingError) {
			return echo.NewHTTPError(http.StatusBadRequest, errors.New("encrypted private key expected"))
		}
		serialised, err := sa.encryptChallenge(body, auditID)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		return c.Blob(http.StatusAccepted, "application/jose", serialised)
	}

	if err := sa.signer.AddSigningKey(body, nil, ""); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log.Info("added signing key")
	return c.NoContent(http.StatusAccepted)
}

func (sa *SignAPI) HandleCaChallenge(c echo.Context) error {
	var actx *auth.AuthContext
	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			actx = claims.AuthContext
		}
	}
	if actx == nil {
		return errors.New("no auth context")
	}
	if !actx.IsValid() {
		return echo.NewHTTPError(http.StatusBadRequest, "auth context is not valid")
	}
	auditID, _ := actx.GetAuthMeta()[auth.MetaAuditID].(string)
	log := Log.WithField("audit_id", auditID)
	passphrase, _ := c.Get("password").(string)
	if passphrase == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "no passphrase given")
	}
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		err = fmt.Errorf("cannot read challenge: %w", err)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	challenge, err := sa.decryptChallenge(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log = log.WithField("original_audit_id", challenge.AuditID)
	if time.Now().After(challenge.Expire) {
		log.Error("attempted use of expired challenge")
		return echo.NewHTTPError(http.StatusForbidden, "the challenge is already expired")
	}
	if err := sa.signer.AddSigningKey(challenge.EncryptedKey, []byte(passphrase), ""); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log.Info("added signing key via challenge")
	return c.NoContent(http.StatusOK)
}

func (sa *SignAPI) HandleGetKey(c echo.Context) error {
	key, err := sa.signer.GetPublicKey()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.Blob(http.StatusOK, "text/plain", ssh.MarshalAuthorizedKey(key))
}

const (
	challengeKeyAlgorithm      = jose.RSA_OAEP_256
	challengeContentEncryption = jose.A256GCM
)

func (sa *SignAPI) encryptChallenge(key []byte, auditID string) ([]byte, error) {
	obj := encryptedChallenge{
		EncryptedKey: key,
		AuditID:      auditID,
		Expire:       time.Now().Add(sa.caChallengeLife),
	}
	plaintext, err := json.Marshal(&obj)
	if err != nil {
		return nil, fmt.Errorf("cannot encode challenge: %w", err)
	}
	encryptor, err := jose.NewEncrypter(challengeContentEncryption,
		jose.Recipient{Algorithm: challengeKeyAlgorithm, Key: sa.caChallengeKey.Public()}, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot init challenge encryptor: %w", err)
	}
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt challenge: %w", err)
	}
	serialised, err := ciphertext.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("cannot encrypt challenge: %w", err)
	}
	return []byte(serialised), nil
}

func (sa *SignAPI) decryptChallenge(challenge []byte) (*encryptedChallenge, error) {
	var obj encryptedChallenge
	parsedCiphertext, err := jose.ParseEncryptedCompact(string(challenge),
		[]jose.KeyAlgorithm{challengeKeyAlgorithm},
		[]jose.ContentEncryption{challengeContentEncryption},
	)
	if err != nil {
		return nil, fmt.Errorf("cannot decode challenge: %w", err)
	}
	plaintext, err := parsedCiphertext.Decrypt(sa.caChallengeKey)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt challenge: %w", err)
	}
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		return nil, fmt.Errorf("cannot parse challenge: %w", err)
	}
	return &obj, nil
}

type encryptedChallenge struct {
	EncryptedKey []byte
	AuditID      string
	Expire       time.Time
}
