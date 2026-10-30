package authldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Documents how the directory treats a simple bind with an empty password
// (an RFC 4513 unauthenticated bind). The backend refuses empty passwords
// before binding regardless.
func TestIntegrationDirectoryRejectsUnauthenticatedBind(t *testing.T) {
	plain, _ := integrationURLs(t)
	conn, err := ldap.DialURL(plain)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	err = conn.UnauthenticatedBind("uid=alice,ou=people,dc=example,dc=com")
	assert.True(t, ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform),
		"OpenLDAP refuses unauthenticated binds by default, got: %v", err)
}
