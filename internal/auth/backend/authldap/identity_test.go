package authldap

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aakso/ssh-inscribe/internal/config"
)

func TestCheckBoundIdentity(t *testing.T) {
	entry := ldap.NewEntry(`CN=Smith\, John (ext),OU=Users,DC=example,DC=com`, map[string][]string{
		"sAMAccountName": {"jsmith"},
	})
	for authzID, ok := range map[string]bool{
		// OpenLDAP and 389 DS normalise the DN, escaping may differ
		`dn:cn=smith\2c john (ext),ou=users,dc=example,dc=com`: true,
		`dn: CN=Smith\, John (ext),OU=Users,DC=example,DC=com`: true,
		`dn:CN=Smith,OU=Users,DC=example,DC=com`:               false,
		`dn:OU=Users,DC=example,DC=com`:                        false,
		`dn:not a dn`:                                          false,
		`dn:`:                                                  false,
		// Active Directory
		`u:EXAMPLE\JSmith`: true,
		`u:jsmith`:         true,
		`u:EXAMPLE\john`:   false,
		`u:EXAMPLE\`:       false,
		`u:`:               false,
		``:                 false,
		`jsmith`:           false,
	} {
		err := checkBoundIdentity(authzID, entry)
		assert.Equal(t, ok, err == nil, "%q: %v", authzID, err)
	}

	noAccountName := ldap.NewEntry(`CN=Smith\, John (ext),OU=Users,DC=example,DC=com`, nil)
	assert.Error(t, checkBoundIdentity(`u:EXAMPLE\jsmith`, noAccountName))
}

func TestUserSearchAttributes(t *testing.T) {
	conf := *Defaults
	al := &AuthLDAP{config: &conf}
	assert.Equal(t, []string{"cn", "displayName"}, al.userSearchAttributes("dn:uid=a"))
	assert.Equal(t, []string{"cn", "displayName", "sAMAccountName"}, al.userSearchAttributes(`u:EXAMPLE\a`))

	conf.UserNamePrincipalAttribute = "uid"
	assert.Equal(t, []string{"cn", "displayName", "uid"}, al.userSearchAttributes(""))
	assert.Equal(t, []string{"cn", "displayName"}, Defaults.UserSearchGetAttributes, "configuration must not change")

	conf.UserNamePrincipal = false
	assert.Equal(t, []string{"cn", "displayName"}, al.userSearchAttributes(""))

	// An empty list returns all attributes, adding one would restrict it
	conf.UserNamePrincipal = true
	conf.UserSearchGetAttributes = nil
	assert.Empty(t, al.userSearchAttributes(`u:EXAMPLE\a`))
}

// verifyBoundIdentity is on unless a configuration turns it off explicitly.
func TestIdentityConfigDecoding(t *testing.T) {
	require.NoError(t, config.LoadBytes([]byte(`
ldapdefault:
  serverURL: ldaps://127.0.0.1:636
ldapcustom:
  serverURL: ldaps://127.0.0.1:636
  verifyboundidentity: false
  userNamePrincipalAttribute: uid
`)))
	a, err := factory("ldapdefault")
	require.NoError(t, err)
	conf := a.(*AuthLDAP).config
	assert.True(t, conf.VerifyBoundIdentity)
	assert.Empty(t, conf.UserNamePrincipalAttribute)

	a, err = factory("ldapcustom")
	require.NoError(t, err)
	conf = a.(*AuthLDAP).config
	assert.False(t, conf.VerifyBoundIdentity)
	assert.Equal(t, "uid", conf.UserNamePrincipalAttribute)
}
