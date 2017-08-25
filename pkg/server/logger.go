package server

import (
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
)

func RequestLogger(lf logrus.Fields) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log := Log.WithFields(lf)
			req := c.Request()
			resp := c.Response()
			start := time.Now()

			ra := req.RemoteAddr
			ra, port, _ := net.SplitHostPort(ra)
			if ip := req.Header.Get(echo.HeaderXRealIP); ip != "" {
				ra = ip
				port = ""
			} else if ip = req.Header.Get(echo.HeaderXForwardedFor); ip != "" {
				ra = ip
				port = ""
			}

			log = log.
				WithField("client", req.Header.Get("User-Agent")).
				WithField("client_version", req.Header.Get("X-Version")).
				WithField("remote_address", ra).
				WithField("remote_port", port).
				WithField("url", req.URL).
				WithField("method", req.Method)

			err := next(c)
			end := time.Now()
			log = log.
				WithField("status", resp.Status).
				WithField("took", end.Sub(start))
			if rid := resp.Header().Get(echo.HeaderXRequestID); rid != "" {
				log = log.WithField("audit_id", rid)
			}
			if err != nil {
				c.Error(err)
				log.WithError(err).
					WithField("status", resp.Status).
					Error(http.StatusText(resp.Status))
				return err
			}
			log.Info(http.StatusText(resp.Status))
			return nil
		}
	}
}
