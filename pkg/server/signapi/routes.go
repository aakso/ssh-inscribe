package signapi

import (
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/random"
)

func (sa *SignApi) RegisterRoutes(g *echo.Group) {
	g.Use(auditID())
	g.GET("/auth", sa.HandleAuthDiscover)
	g.POST("/auth/:name",
		sa.HandleLogin,
		userPasswordForward(),
		jwtAuth(sa.tkey, &SignClaim{}, true),
	)
	g.POST("/sign", sa.HandleSign, jwtAuth(sa.tkey, &SignClaim{}, false))
	g.GET("/ca", sa.HandleGetKey)
	g.POST("/ca", sa.HandleAddKey, jwtAuth(sa.tkey, &SignClaim{}, false))
	g.GET("/ready", sa.HandleReady)
}

func userPasswordForward() echo.MiddlewareFunc {
	return middleware.BasicAuth(func(user string, pw string, c echo.Context) bool {
		c.Set("username", user)
		c.Set("password", pw)
		return true
	})
}

func jwtAuth(key []byte, claims jwt.Claims, skipIfMissing bool) echo.MiddlewareFunc {
	const authHeader = "X-Auth"
	config := middleware.JWTConfig{
		SigningKey:  key,
		TokenLookup: "header:" + authHeader,
		Claims:      claims,
	}
	if skipIfMissing {
		config.Skipper = func(c echo.Context) bool {
			if c.Request().Header.Get(authHeader) == "" {
				return true
			}
			return false
		}
	}
	return middleware.JWTWithConfig(config)
}

func auditID() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			rid := random.String(32)
			c.Response().Header().Set(echo.HeaderXRequestID, rid)
			return next(c)
		}
	}
}
