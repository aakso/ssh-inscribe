package signapi

import (
	"fmt"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/random"
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
	g.GET("/ready", sa.HandleReady)
}

func userPasswordForward(skipper middleware.Skipper) echo.MiddlewareFunc {
	return middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		Validator: func(user string, pw string, c echo.Context) bool {
			fmt.Println("in userpw")
			c.Set("username", user)
			c.Set("password", pw)
			return true
		},
		Skipper: skipper,
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
