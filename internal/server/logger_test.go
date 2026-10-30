package server

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactURL(t *testing.T) {
	u, _ := url.Parse("/v1/auth_callback/oidc?code=secret&state=abc")
	assert.Equal(t, "/v1/auth_callback/oidc?code=REDACTED&state=abc", redactURL(u))

	u, _ = url.Parse("/v1/sign?include_principals=a%2A")
	assert.Equal(t, "/v1/sign?include_principals=a%2A", redactURL(u))
}
