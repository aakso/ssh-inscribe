package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/aakso/ssh-inscribe/internal/globals"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	authbackend "github.com/aakso/ssh-inscribe/internal/auth/backend"
	"github.com/aakso/ssh-inscribe/internal/config"
	"github.com/aakso/ssh-inscribe/internal/keysigner"
	"github.com/aakso/ssh-inscribe/internal/server/signapi"
	"github.com/aakso/ssh-inscribe/internal/util"
)

type Server struct {
	config *Config
	web    *echo.Echo

	// APIs
	signapi *signapi.SignApi
}

func (s *Server) Start() error {
	var err error
	log := Log.WithField("server_version", globals.Version())
	s.web.Logger.SetOutput(io.Discard)

	cc, err := s.config.GetCertificateMap()
	if err != nil {
		return errors.Wrap(err, "invalid certificate configuration")
	}

	if len(cc.Certificates) > 0 {
		// Configure TLSServer before starting
		tlsServer := s.web.TLSServer
		tlsServer.TLSConfig = new(tls.Config)

		if len(cc.Certificates) == 1 {
			tlsServer.TLSConfig.Certificates = make([]tls.Certificate, 1)
			tlsServer.TLSConfig.Certificates[0] = cc.Certificates[0]
		} else {
			tlsServer.TLSConfig.NameToCertificate = cc.CertificateMap //nolint:staticcheck // user config
			tlsServer.TLSConfig.Certificates = cc.Certificates
		}

		tlsServer.Addr = s.config.Listen
		if !s.web.DisableHTTP2 {
			tlsServer.TLSConfig.NextProtos = append(tlsServer.TLSConfig.NextProtos, "h2")
		}
		log.WithField("listen", fmt.Sprintf("https://%s", s.config.Listen)).WithField(
			"certificates", fmt.Sprintf("%d", len(cc.Certificates))).Info("server starting")

		err = s.web.StartServer(tlsServer)
		if err != nil {
			return errors.Wrap(err, "cannot start server")
		}
	} else {
		log.WithField("listen", fmt.Sprintf("http://%s", s.config.Listen)).Warn("server starting without TLS")
		err = s.web.Start(s.config.Listen)
	}
	if err != nil {
		return errors.Wrap(err, "cannot start server")
	}
	return nil
}

func (s *Server) initApi() {
	s.web.Use(RecoverHandler(Log.Data))
	s.web.HTTPErrorHandler = errorHandler
	s.web.Use(RequestLogger(Log.Data))
	s.web.Use(middleware.BodyLimit("1M"))
	g := s.web.Group("/v1")
	s.signapi.RegisterRoutes(g)
	s.web.GET("/version", handleVersion)
}

func Build() (*Server, error) {
	// Configuration
	tmp, err := config.Get("server")
	if err != nil {
		return nil, errors.Wrap(err, "cannot initialize server")
	}
	conf, _ := tmp.(*Config)
	if conf == nil {
		return nil, errors.New("cannot initialize server. Invalid configuration")
	}
	maxlife, err := time.ParseDuration(conf.MaxCertLifetime)
	if err != nil {
		return nil, errors.Wrap(err, "invalid MaxCertLifeTime")
	}
	defaultlife, err := time.ParseDuration(conf.DefaultCertLifetime)
	if err != nil {
		return nil, errors.Wrap(err, "invalid DefaultCertLifetime")
	}
	caChallengeLife, err := time.ParseDuration(conf.CaChallengeLifetime)
	if err != nil {
		return nil, errors.Wrap(err, "invalid CaChallengeLifetime")
	}

	// Auth backends
	authList := []signapi.AuthenticatorListEntry{}
	for _, ab := range conf.AuthBackends {
		instance, err := authbackend.GetBackend(ab.Type, ab.Config)
		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize server")
		}
		authList = append(authList, signapi.AuthenticatorListEntry{
			Authenticator: instance,
			Default:       ab.Default,
		})
	}

	signer := keysigner.New(conf.AgentSocket, conf.CertSigningKeyFingerprint)
	for i := 0; i < 3; i++ {
		if signer.AgentPing() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Setup PKCS11 if required
	if conf.PKCS11Provider != "" && conf.PKCS11Pin != "" {
		// Try to readd (NitroKey issue)
		if err = signer.RemoveSmartcard(conf.PKCS11Provider); err != nil {
			return nil, errors.Wrap(err, "pkcs11 initialize error")
		}
		if err := signer.AddSmartcard(conf.PKCS11Provider, conf.PKCS11Pin); err != nil {
			return nil, errors.Wrap(err, "pkcs11 initialize error")
		}
	}

	// Generate random jwt token signing key in case none is set
	if conf.TokenSigningKey == "" {
		Log.Info("generating random JWT token signing key as none is set")
		conf.TokenSigningKey = util.RandB64(256)
	}

	// Signing API
	signapi := signapi.New(authList, signer, []byte(conf.TokenSigningKey), defaultlife, maxlife, caChallengeLife)

	s := &Server{
		config:  conf,
		web:     echo.New(),
		signapi: signapi,
	}
	s.initApi()
	return s, nil
}

func handleVersion(c echo.Context) error {
	return c.String(http.StatusOK, fmt.Sprint(globals.Version()))
}

// Simplified version of the standard echo's errorhandler
func errorHandler(err error, c echo.Context) {
	var (
		code = http.StatusInternalServerError
		msg  interface{}
	)
	if he, ok := err.(*echo.HTTPError); ok {
		code = he.Code
		msg = he.Message
	} else {
		msg = http.StatusText(code)
	}
	if !c.Response().Committed {
		var rErr error
		if c.Request().Method == echo.HEAD { // Issue #608
			rErr = c.NoContent(code)
		} else {
			rErr = c.String(code, fmt.Sprintf("%s", msg))
		}
		if rErr != nil {
			Log.WithError(rErr).Warn("error sending error response")
		}
	}
}

// Simplified version of the echo's recover handler with support for logrus logging
func RecoverHandler(lf logrus.Fields) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					var err error
					log := Log.WithFields(lf)
					switch r := r.(type) {
					case error:
						err = r
					default:
						err = fmt.Errorf("%v", r)
					}
					stack := make([]byte, 4<<10)
					length := runtime.Stack(stack, false)
					log.WithError(err).WithField("stack", string(stack[:length])).Error("PANIC RECOVER")
					c.Error(err)
				}
			}()
			return next(c)
		}
	}
}
