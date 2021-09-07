package signapi

import (
	"crypto"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth/authz/authzfilter"

	jwt "github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/pkg/auth"
)

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

	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		err = errors.Wrap(err, "cannot read public key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(body)
	if err != nil {
		err = errors.Wrap(err, "cannot parse public key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	cert := auth.MakeCertificate(pubKey, actx)
	cert.ValidBefore = uint64(time.Now().Add(sa.defaultCertLife).Unix())
	// Validity
	if exp := c.QueryParam("expires"); exp != "" {
		ts, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			err = errors.Wrap(err, "invalid expires")
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		if time.Until(ts) > sa.maxCertLife {
			return echo.NewHTTPError(http.StatusBadRequest, errors.Errorf("maxmimum lifetime is %s", sa.maxCertLife).Error())
		}
		cert.ValidBefore = uint64(ts.Unix())
	}

	var opts crypto.SignerOpts
	switch c.QueryParam("signing_option") {
	case "":
	case "rsa-sha2-256":
		opts = crypto.SHA256
	case "rsa-sha2-512":
		opts = crypto.SHA512
	default:
		return echo.NewHTTPError(http.StatusBadRequest, errors.New("invalid signing_option"))
	}

	if err := sa.signer.SignCertificate(cert, opts); err != nil {
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
	return c.Blob(http.StatusOK, "text/plain", ssh.MarshalAuthorizedKey(cert))
}
