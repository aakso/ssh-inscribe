package signapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"gopkg.in/square/go-jose.v2"

	"github.com/aakso/ssh-inscribe/pkg/auth"
)

func (sa *SignApi) HandleAddKey(c echo.Context) error {
	var actx *auth.AuthContext
	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			actx = claims.AuthContext
		}
	}
	if actx == nil {
		return errors.New("no auth context")
	}
	auditId, _ := actx.GetAuthMeta()[auth.MetaAuditID].(string)
	log := Log.WithField("audit_id", auditId)

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		err = errors.Wrap(err, "cannot read private key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Encrypted CA challenge
	if v, _ := strconv.ParseBool(c.QueryParam("init_challenge")); v {
		_, err := ssh.ParseRawPrivateKey(body)
		if _, ok := err.(*ssh.PassphraseMissingError); !ok {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Errorf("encrypted private key expectec"))
		}
		serialised, err := sa.encryptChallenge(body, auditId)
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

func (sa *SignApi) HandleCaChallenge(c echo.Context) error {
	var actx *auth.AuthContext
	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			actx = claims.AuthContext
		}
	}
	if actx == nil {
		return errors.New("no auth context")
	}
	auditId, _ := actx.GetAuthMeta()[auth.MetaAuditID].(string)
	log := Log.WithField("audit_id", auditId)
	passphrase, _ := c.Get("password").(string)
	if passphrase == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "no passphrase given")
	}
	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		err = errors.Wrap(err, "cannot read challenge")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	challenge, err := sa.decryptChallenge(body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log = log.WithField("original_audit_id", challenge.AuditId)
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

func (sa *SignApi) HandleGetKey(c echo.Context) error {
	if key, err := sa.signer.GetPublicKey(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	} else {
		return c.Blob(http.StatusOK, "text/plain", ssh.MarshalAuthorizedKey(key))
	}
}

func (sa *SignApi) encryptChallenge(key []byte, auditId string) ([]byte, error) {
	obj := encryptedChallenge{
		EncryptedKey: key,
		AuditId:      auditId,
		Expire:       time.Now().Add(sa.caChallengeLife),
	}
	plaintext, err := json.Marshal(&obj)
	if err != nil {
		return nil, errors.Wrap(err, "cannot encode challenge")
	}
	encryptor, err := jose.NewEncrypter(jose.A128GCM,
		jose.Recipient{Algorithm: jose.RSA_OAEP, Key: sa.caChallengeKey.Public()}, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot init challenge encryptor")
	}
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, errors.Wrap(err, "cannot encrypt challenge")
	}
	serialised, err := ciphertext.CompactSerialize()
	if err != nil {
		return nil, errors.Wrap(err, "cannot encrypt challenge")
	}
	return []byte(serialised), nil
}

func (sa *SignApi) decryptChallenge(challenge []byte) (*encryptedChallenge, error) {
	var obj encryptedChallenge
	parsedCiphertext, err := jose.ParseEncrypted(string(challenge))
	if err != nil {
		return nil, errors.Wrap(err, "cannot decode challenge")
	}
	plaintext, err := parsedCiphertext.Decrypt(sa.caChallengeKey)
	if err != nil {
		return nil, errors.Wrap(err, "cannot decrypt challenge")
	}
	if err := json.Unmarshal(plaintext, &obj); err != nil {
		return nil, errors.Wrap(err, "cannot parse challenge")
	}
	return &obj, nil
}

type encryptedChallenge struct {
	EncryptedKey []byte
	AuditId      string
	Expire       time.Time
}
