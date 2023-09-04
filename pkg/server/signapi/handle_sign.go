package signapi

import (
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth/authz/authzfilter"
	"github.com/aakso/ssh-inscribe/pkg/util"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/pkg/auth"
)

const minimumPrincipalsBatchSize = 10

func (sa *SignApi) HandleSign(c echo.Context) error {
	var actx *auth.AuthContext
	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			actx = claims.AuthContext
		}
	}
	if actx == nil {
		return errors.New("no auth context")
	}
	log := Log.WithField("audit_id", actx.GetAuthMeta()[auth.MetaAuditID])

	if !actx.IsValid() {
		return echo.NewHTTPError(http.StatusBadRequest, "auth context is not valid")
	}

	// User requests to filter principals
	principalsInclude := c.QueryParam("include_principals")
	principalsExclude := c.QueryParam("exclude_principals")
	if principalsInclude != "" || principalsExclude != "" {
		// Special use case for authzfilter
		var authz auth.Authorizer
		authz, err := authzfilter.NewPrincipalFilter(authzfilter.PrincipalFilterConfig{
			FilterIncludePrincipalsGlob: principalsInclude,
			FilterExcludePrincipalsGlob: principalsExclude,
		})
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, errors.Wrap(err, "cannot parse principal filter"))
		}
		if ctx, ok := authz.Authorize(actx); !ok {
			log.Error("user requested principal filter failed, this should not happen")
			return echo.ErrUnauthorized
		} else {
			actx = ctx
		}
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		err = errors.Wrap(err, "cannot read public key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		err = errors.Wrap(err, "cannot parse public key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	validBefore := time.Now().Add(sa.defaultCertLife)

	// Validity
	if exp := c.QueryParam("expires"); exp != "" {
		validBefore, err = time.Parse(time.RFC3339, exp)
		if err != nil {
			err = errors.Wrap(err, "invalid expires")
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if time.Until(validBefore) > sa.maxCertLife {
			return echo.NewHTTPError(http.StatusBadRequest, errors.Errorf("maximum lifetime is %s", sa.maxCertLife).Error())
		}
	}

	// Max principals per certificate
	var maxPrincipalsPerCertificate int64
	if sval := c.QueryParam("max_principals_per_certificate"); sval != "" {
		maxPrincipalsPerCertificate, err = strconv.ParseInt(sval, 10, 64)
		if err != nil {
			err = errors.Wrap(err, "invalid max_principals_per_certificate")
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if maxPrincipalsPerCertificate < minimumPrincipalsBatchSize {
			return echo.NewHTTPError(http.StatusBadRequest,
				errors.Errorf("minimum value for max_principals_per_certificate is %d", minimumPrincipalsBatchSize))
		}
	}

	certs := auth.MakeCertificates(pubKey, actx, validBefore, int(maxPrincipalsPerCertificate))

	// Signing option
	var algo string
	switch c.QueryParam("signing_option") {
	case "":
		algo = util.DefaultRSAKeyAlgorithm
	case "ssh-rsa":
		algo = ssh.KeyAlgoRSA
	case "rsa-sha2-256":
		algo = ssh.KeyAlgoRSASHA256
	case "rsa-sha2-512":
		algo = ssh.KeyAlgoRSASHA512
	default:
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("invalid signing_option"))
	}

	var marshaledCerts []byte
	for _, cert := range certs {
		if err := sa.signer.SignCertificate(cert, algo); err != nil {
			err = errors.Wrap(err, "cannot sign")
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
		log.
			WithField("key_id", cert.KeyId).
			WithField("principals", cert.ValidPrincipals).
			WithField("critical_options", cert.CriticalOptions).
			WithField("extensions", cert.Extensions).
			WithField("not_before", time.Unix(int64(cert.ValidAfter), 0)).
			WithField("expires", time.Unix(int64(cert.ValidBefore), 0)).
			WithField("pubkey_fp", ssh.FingerprintSHA256(pubKey)).
			WithField("pubkey_fp_md5", ssh.FingerprintLegacyMD5(pubKey)).
			WithField("signature_format", cert.Signature.Format).
			Info("issued certificate")
		marshaledCerts = append(marshaledCerts, ssh.MarshalAuthorizedKey(cert)...)
	}
	return c.Blob(http.StatusOK, "text/plain", marshaledCerts)
}
