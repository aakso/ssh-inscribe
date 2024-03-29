package signapi

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/random"
	"github.com/pkg/errors"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

func (sa *SignApi) RegisterRoutes(g *echo.Group) {
	g.GET("/auth", sa.HandleAuthDiscover)
	g.POST("/auth/:name",
		sa.HandleLogin,
		userPasswordForward(sa.LoginUserPasswordAuthSkipper),
		jwtAuth(sa.tkey, &SignClaim{}, true),
		auditID(),
	)
	g.GET("/auth_callback/:name", sa.HandleAuthCallback)
	g.POST("/auth_callback/:name", sa.HandleAuthCallback)
	g.POST("/sign", sa.HandleSign, jwtAuth(sa.tkey, &SignClaim{}, false), auditID())
	g.GET("/ca", sa.HandleGetKey)
	g.POST("/ca", sa.HandleAddKey, jwtAuth(sa.tkey, &SignClaim{}, false), auditID())
	g.POST("/ca/response", sa.HandleCaChallenge, jwtAuth(sa.tkey, &SignClaim{}, false),
		userPasswordForward(nil), auditID())
	g.GET("/ready", sa.HandleReady)
}

func userPasswordForward(skipper middleware.Skipper) echo.MiddlewareFunc {
	return middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		Validator: func(user string, pw string, c echo.Context) (bool, error) {
			c.Set("username", user)
			c.Set("password", pw)
			return true, nil
		},
		Skipper: skipper,
	})
}

func jwtAuth(key []byte, claims jwt.Claims, skipIfMissing bool) echo.MiddlewareFunc {
	const authHeader = "X-Auth"
	config := echojwt.Config{
		SigningKey:  key,
		TokenLookup: "header:" + authHeader,
		// ref: https://echo.labstack.com/middleware/jwt/
		ParseTokenFunc: func(c echo.Context, auth string) (interface{}, error) {
			keyFunc := func(t *jwt.Token) (interface{}, error) {
				if t.Method.Alg() != "HS256" {
					return nil, errors.Errorf("unexpected jwt signing method=%v", t.Header["alg"])
				}
				return key, nil
			}

			auth = strings.TrimPrefix(auth, "Bearer ")
			// claims are of type `jwt.MapClaims` when token is created with `jwt.Parse`
			token, err := jwt.ParseWithClaims(auth, claims, keyFunc)
			if err != nil {
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			return token, nil
		},
	}
	if skipIfMissing {
		config.Skipper = func(c echo.Context) bool {
			return c.Request().Header.Get(authHeader) == ""
		}
	}
	return echojwt.WithConfig(config)
}

func auditID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			var (
				actx   *auth.AuthContext
				claims *SignClaim
			)
			// Lookup audit key from the jwt token if possible
			if token, _ := c.Get("user").(*jwt.Token); token != nil {
				claims, _ = token.Claims.(*SignClaim)
			}
			if claims != nil {
				actx = claims.AuthContext
			}
			if actx != nil {
				if aid := actx.GetMetaString(auth.MetaAuditID); aid != "" {
					c.Response().Header().Set(echo.HeaderXRequestID, aid)
				}
			} else {
				// Instantiate new audit id otherwise
				rid := random.String(32)
				c.Response().Header().Set(echo.HeaderXRequestID, rid)
			}
			return next(c)
		}
	}
}
