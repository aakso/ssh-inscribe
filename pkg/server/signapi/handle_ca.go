package signapi

import (
	"io/ioutil"
	"net/http"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
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
	log := Log.WithField("audit_id", actx.GetAuthMeta()[auth.MetaAuditID])

	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		err = errors.Wrap(err, "cannot read private key")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := sa.signer.AddSigningKey(body, ""); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	log.Info("added signing key")
	return c.NoContent(http.StatusAccepted)
}

func (sa *SignApi) HandleGetKey(c echo.Context) error {
	if key, err := sa.signer.GetPublicKey(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	} else {
		return c.Blob(http.StatusOK, "text/plain", ssh.MarshalAuthorizedKey(key))
	}
}
