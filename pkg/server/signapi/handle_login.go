package signapi

import (
	"net/http"
	"net/url"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/pkg/errors"
)

func (sa *SignApi) HandleLogin(c echo.Context) error {
	var parentCtx *auth.AuthContext
	name, _ := url.PathUnescape(c.Param("name"))
	ab, ok := sa.auth[name]
	if !ok {
		return echo.ErrNotFound
	}

	if token, _ := c.Get("user").(*jwt.Token); token != nil {
		if claims, _ := token.Claims.(*SignClaim); claims != nil {
			parentCtx = claims.AuthContext
		}
	}

	user, _ := c.Get("username").(string)
	pw, _ := c.Get("password").(string)
	creds := &auth.Credentials{
		UserIdentifier: user,
		Secret:         []byte(pw),
		Meta: map[string]interface{}{
			auth.MetaAuditID: c.Response().Header().Get(echo.HeaderXRequestID),
		},
	}
	actx, ok := ab.Authenticate(parentCtx, creds)
	if !ok {
		return echo.ErrUnauthorized
	}
	claims := SignClaim{
		AuthContext: actx,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * TokenLifeSecs).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sa.tkey)
	if err != nil {
		return errors.Wrap(err, "cannot sign token")
	}
	return c.Blob(http.StatusOK, "application/jwt", []byte(signed))
}
