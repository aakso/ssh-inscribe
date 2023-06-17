package signapi

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"

	"github.com/aakso/ssh-inscribe/pkg/auth"
)

const (
	MaxAuthContextChainLength = 8
)

func (sa *SignApi) LoginUserPasswordAuthSkipper(c echo.Context) bool {
	name, _ := url.PathUnescape(c.Param("name"))
	if ab, ok := sa.auth[name]; ok {
		if ab.CredentialType() == auth.CredentialFederated {
			return true
		}
	}
	return false
}

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

	if parentCtx != nil && parentCtx.Len() > MaxAuthContextChainLength {
		return echo.NewHTTPError(http.StatusBadRequest, "auth context chain too long")
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

	token := sa.makeToken(actx)
	signed, err := token.SignedString(sa.tkey)
	if err != nil {
		return errors.Wrap(err, "cannot sign token")
	}

	if actx.Status == auth.StatusPending {
		// Federated login redirect
		if redirectURL := actx.GetMetaString(auth.MetaFederationAuthURL); redirectURL != "" {
			c.Response().Header().Set(echo.HeaderContentType, "application/jwt")
			c.Response().Header().Set(echo.HeaderLocation, redirectURL)
			c.Response().WriteHeader(http.StatusSeeOther)
			_, err := fmt.Fprint(c.Response().Writer, signed)
			return err
		}
	}

	return c.Blob(http.StatusOK, "application/jwt", []byte(signed))
}

func (sa *SignApi) HandleAuthCallback(c echo.Context) error {
	name, _ := url.PathUnescape(c.Param("name"))
	ab, ok := sa.auth[name]
	if !ok {
		return echo.ErrNotFound
	}

	fa, ok := ab.(auth.FederatedAuthenticator)
	if !ok {
		return echo.ErrNotFound
	}

	params, err := c.FormParams()
	if err != nil {
		params = c.QueryParams()
	}

	if err := fa.FederationCallback(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	return c.String(http.StatusOK, "Authentication successful, you can close the window now")
}
