package server

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func RequestLogger(lf logrus.Fields) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log := Log.WithFields(lf)
			req := c.Request()
			resp := c.Response()
			start := time.Now()

			peer, port, _ := net.SplitHostPort(req.RemoteAddr)
			ra := peer
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
				WithField("peer_address", peer).
				WithField("url", redactURL(req.URL)).
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

// Query parameters that carry credentials and must not end up in logs.
var sensitiveQueryParams = []string{"code"}

func redactURL(u *url.URL) string {
	q := u.Query()
	redacted := false
	for _, k := range sensitiveQueryParams {
		if q.Has(k) {
			q.Set(k, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return u.String()
	}
	c := *u
	c.RawQuery = q.Encode()
	return c.String()
}
