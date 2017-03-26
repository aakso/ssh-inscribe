package signapi

import (
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
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

	if err := sa.signer.SignCertificate(cert); err != nil {
		err = errors.Wrap(err, "cannot sign")
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log.
		WithField("key_id", cert.KeyId).
		WithField("expires", time.Unix(int64(cert.ValidBefore), 0)).
		Info("issued certificate")
	return c.Blob(http.StatusOK, "text/plain", ssh.MarshalAuthorizedKey(cert))
}
