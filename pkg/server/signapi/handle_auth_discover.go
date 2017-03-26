package signapi

import (
	"net/http"

	"github.com/aakso/ssh-inscribe/pkg/server/signapi/objects"
	"github.com/labstack/echo"
)

func (sa *SignApi) HandleAuthDiscover(c echo.Context) error {
	var r []objects.DiscoverResult
	for _, auth := range sa.auth {
		r = append(r, objects.DiscoverResult{
			AuthenticatorName:           auth.Name(),
			AuthenticatorRealm:          auth.Realm(),
			AuthenticatorCredentialType: auth.CredentialType(),
		})
	}
	return c.JSON(http.StatusOK, r)
}
