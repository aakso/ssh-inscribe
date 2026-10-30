package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestServer(conf *Config) *Server {
	s := &Server{config: conf, web: echo.New()}
	s.web.HideBanner = true
	s.web.HidePort = true
	s.web.HTTPErrorHandler = errorHandler
	s.web.GET("/ping", func(c echo.Context) error { return c.String(http.StatusOK, "pong") })
	return s
}

func assertTimeouts(t *testing.T, srv *http.Server) {
	t.Helper()
	assert.Equal(t, 10*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, srv.ReadTimeout)
	assert.Equal(t, 2*time.Minute, srv.WriteTimeout)
	assert.Equal(t, 2*time.Minute, srv.IdleTimeout)
}

func TestConfigurePlain(t *testing.T) {
	s := newTestServer(&Config{Listen: "127.0.0.1:0"})
	srv, err := s.configure()
	require.NoError(t, err)
	assert.Same(t, s.web.Server, srv)
	assert.Nil(t, srv.TLSConfig)
	assert.Equal(t, "127.0.0.1:0", srv.Addr)
	assertTimeouts(t, srv)
}

func TestConfigureInvalidCertificates(t *testing.T) {
	s := newTestServer(&Config{TLSCertFile: "/nonexistent.crt", TLSKeyFile: "/nonexistent.key"})
	_, err := s.configure()
	assert.Error(t, err)
}

func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	aCert, aKey := writeCert(t, dir, "a.example.com")
	wCert, wKey := writeCert(t, dir, "wild.example.org")
	s := newTestServer(&Config{
		Listen:       "127.0.0.1:0",
		TLSCertFiles: []string{aCert, wCert},
		TLSKeyFiles:  []string{aKey, wKey},
		TLSCertNames: []string{"a.example.com", "*.example.org"},
	})
	srv, err := s.configure()
	require.NoError(t, err)
	assertTimeouts(t, srv)
	assert.Equal(t, uint16(tls.VersionTLS12), srv.TLSConfig.MinVersion)

	go func() { _ = s.web.StartServer(srv) }()
	t.Cleanup(func() { _ = s.web.Close() })
	var addr net.Addr
	require.Eventually(t, func() bool {
		addr = s.web.TLSListenerAddr()
		return addr != nil
	}, 5*time.Second, 10*time.Millisecond)

	dial := func(serverName string, maxVersion uint16) (*tls.Conn, error) {
		d := &tls.Dialer{Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, //nolint:gosec // self-signed test certificates; the presented certificate is checked below
			MaxVersion:         maxVersion,
		}}
		conn, err := d.DialContext(t.Context(), "tcp", addr.String())
		if err != nil {
			return nil, err
		}
		return conn.(*tls.Conn), nil
	}

	t.Run("SelectsCertificateBySNI", func(t *testing.T) {
		for serverName, want := range map[string]string{
			"a.example.com": "a.example.com",
			"x.example.org": "wild.example.org",
		} {
			conn, err := dial(serverName, 0)
			if !assert.NoError(t, err) {
				continue
			}
			peer := conn.ConnectionState().PeerCertificates[0]
			_ = conn.Close()
			assert.Equal(t, want, peer.Subject.CommonName, serverName)
		}
	})

	t.Run("RejectsTLS11", func(t *testing.T) {
		conn, err := dial("a.example.com", tls.VersionTLS11)
		if err == nil {
			_ = conn.Close()
		}
		assert.Error(t, err)
	})

	t.Run("ServesRequests", func(t *testing.T) {
		pool := x509.NewCertPool()
		conn, err := dial("a.example.com", 0)
		require.NoError(t, err)
		pool.AddCert(conn.ConnectionState().PeerCertificates[0])
		_ = conn.Close()

		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "a.example.com", MinVersion: tls.VersionTLS12},
		}}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+addr.String()+"/ping", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestErrorHandler(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = errorHandler
	e.GET("/http", func(echo.Context) error { return echo.NewHTTPError(http.StatusTeapot, "short and stout") })
	e.HEAD("/http", func(echo.Context) error { return echo.NewHTTPError(http.StatusTeapot, "short and stout") })
	e.GET("/internal", func(echo.Context) error { return errors.New("secret internal detail") })
	e.GET("/wrapped", func(echo.Context) error {
		return errors.Join(errors.New("context"), echo.NewHTTPError(http.StatusForbidden, "denied"))
	})

	for _, tc := range []struct {
		method, path string
		code         int
		body         string
	}{
		{http.MethodGet, "/http", http.StatusTeapot, "short and stout"},
		{http.MethodHead, "/http", http.StatusTeapot, ""},
		{http.MethodGet, "/internal", http.StatusInternalServerError, "Internal Server Error"},
		{http.MethodGet, "/wrapped", http.StatusForbidden, "denied"},
	} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), tc.method, tc.path, nil))
		assert.Equal(t, tc.code, rec.Code, tc.path)
		assert.Equal(t, tc.body, rec.Body.String(), tc.path)
	}
}

func TestRecoverHandler(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = errorHandler
	e.Use(RecoverHandler(nil))
	e.GET("/panic", func(echo.Context) error { panic("boom") })

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/panic", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "boom", "panic details must not reach the client")
}

func TestRequestLogger(t *testing.T) {
	hook := logtest.NewLocal(Log.Logger)
	t.Cleanup(hook.Reset)

	e := echo.New()
	e.Use(RequestLogger(nil))
	e.GET("/v1/auth_callback/oidc", func(c echo.Context) error { return c.NoContent(http.StatusOK) })

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/auth_callback/oidc?code=secret&state=abc", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set(echo.HeaderXForwardedFor, "198.51.100.7")
	e.ServeHTTP(httptest.NewRecorder(), req)

	entry := hook.LastEntry()
	require.NotNil(t, entry)
	assert.Equal(t, logrus.InfoLevel, entry.Level)
	assert.Equal(t, "198.51.100.7", entry.Data["remote_address"])
	assert.Equal(t, "192.0.2.1", entry.Data["peer_address"], "the TCP peer must be logged regardless of headers")
	assert.Equal(t, "/v1/auth_callback/oidc?code=REDACTED&state=abc", entry.Data["url"])
	assert.Equal(t, http.StatusOK, entry.Data["status"])
}
