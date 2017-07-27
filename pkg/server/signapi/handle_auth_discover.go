package signapi

import (
	"net/http"

	"github.com/aakso/ssh-inscribe/pkg/server/signapi/objects"
	"github.com/labstack/echo"
)

func (sa *SignApi) HandleAuthDiscover(c echo.Context) error {
	var r []objects.DiscoverResult
	for _, v := range sa.authList {
		r = append(r, objects.DiscoverResult{
			AuthenticatorName:           v.Authenticator.Name(),
			AuthenticatorRealm:          v.Authenticator.Realm(),
			AuthenticatorCredentialType: v.Authenticator.CredentialType(),
			Default:                     v.Default,
		})
	}
	return c.JSON(http.StatusOK, r)
}
