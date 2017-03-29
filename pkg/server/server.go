package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	authbackend "github.com/aakso/ssh-inscribe/pkg/auth/backend"
	"github.com/aakso/ssh-inscribe/pkg/config"
	"github.com/aakso/ssh-inscribe/pkg/keysigner"
	"github.com/aakso/ssh-inscribe/pkg/server/signapi"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/pkg/errors"
)

type Server struct {
	config *Config
	web    *echo.Echo

	// APIs
	signapi *signapi.SignApi
}

func (s *Server) Start() error {
	var err error
	s.web.Logger.SetOutput(ioutil.Discard)
	certFile, keyFile := s.config.TLSCertFile, s.config.TLSKeyFile
	if certFile != "" && keyFile != "" {
		err = s.web.StartTLS(s.config.Listen, certFile, keyFile)
	} else {
		err = s.web.Start(s.config.Listen)
	}
	if err != nil {
		return errors.Wrap(err, "cannot start server")
	}
	return nil
}

func (s *Server) initApi() {
	s.web.HTTPErrorHandler = errorHandler
	s.web.Use(middleware.Recover())
	s.web.Use(RequestLogger(Log))
	s.web.Use(middleware.BodyLimit("1M"))
	g := s.web.Group("/v1")
	s.signapi.RegisterRoutes(g)
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

	// Auth backends
	auths := map[string]auth.Authenticator{}
	for _, ab := range conf.AuthBackends {
		instance, err := authbackend.GetBackend(ab.Type, ab.Config)
		if err != nil {
			return nil, errors.Wrap(err, "cannot initialize server")
		}
		auths[instance.Name()] = instance
	}

	signer := keysigner.New(conf.AgentSocket)
	for i := 0; i < 3; i++ {
		if signer.AgentPing() {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Setup PKCS11 if required
	if conf.PKCS11Provider != "" && conf.PKCS11Pin != "" {
		// Try to readd (NitroKey issue)
		signer.RemoveSmartcard(conf.PKCS11Provider)
		if err := signer.AddSmartcard(conf.PKCS11Provider, conf.PKCS11Pin); err != nil {
			return nil, errors.Wrap(err, "pkcs11 initialize error")
		}
	}

	// Signing API
	signapi := signapi.New(
		auths,
		signer,
		[]byte(conf.TokenSigningKey),
		defaultlife,
		maxlife,
	)

	s := &Server{
		config:  conf,
		web:     echo.New(),
		signapi: signapi,
	}
	s.initApi()
	return s, nil
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
		if c.Request().Method == echo.HEAD { // Issue #608
			c.NoContent(code)
		} else {
			c.String(code, fmt.Sprintf("%s", msg))
		}
	}
}
