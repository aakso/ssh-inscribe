package signapi

import (
	"net/http"

	"github.com/labstack/echo"
)

func (sa *SignApi) HandleReady(c echo.Context) error {
	if !sa.signer.Ready() {
		return echo.NewHTTPError(http.StatusInternalServerError, "signing service is not ready for signing")
	}

	return c.NoContent(http.StatusNoContent)
}
