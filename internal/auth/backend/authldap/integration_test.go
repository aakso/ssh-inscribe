package authldap

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/config"
)

// Integration tests against a real directory server, run by
// test/ldap/run-openldap.sh. They only use the exported API and the factory
// so that the same file can be run against older versions for comparison.

func integrationURLs(t *testing.T) (plain, ldaps string) {
	t.Helper()
	plain, ldaps = os.Getenv("LDAPIT_PLAIN_URL"), os.Getenv("LDAPIT_LDAPS_URL")
	if plain == "" || ldaps == "" {
		t.Skip("LDAPIT_PLAIN_URL and LDAPIT_LDAPS_URL not set, see test/ldap/run-openldap.sh")
	}
	return plain, ldaps
}

// integrationConfig is a typical OpenLDAP configuration.
func integrationConfig(serverURL string) *Config {
	conf := *Defaults
	conf.ServerURL = serverURL
	conf.Timeout = 5
	conf.UserBindDN = "uid={{.UserName}},ou=people,dc=example,dc=com"
	conf.UserSearchBase = "ou=people,dc=example,dc=com"
	conf.UserSearchFilter = "(&(objectClass=inetOrgPerson)(uid={{.UserName}}))"
	conf.GroupSearchBase = "ou=groups,dc=example,dc=com"
	conf.GroupSearchFilter = "(&(objectClass=groupOfNames)(member={{.User.DN}}))"
	conf.SubjectNameTemplate = "{{.User.displayName}}"
	conf.PrincipalTemplate = "{{.Group.cn}}"
	conf.UserNamePrincipal = true
	return &conf
}

func integrationLogin(t *testing.T, conf *Config, user, password string) (*auth.AuthContext, bool) {
	t.Helper()
	al, err := New(conf)
	require.NoError(t, err)
	return al.Authenticate(nil, &auth.Credentials{
		UserIdentifier: user,
		Secret:         []byte(password),
		Meta:           map[string]any{},
	})
}

func TestIntegrationLogin(t *testing.T) {
	plain, _ := integrationURLs(t)
	actx, ok := integrationLogin(t, integrationConfig(plain), "alice", "secret")
	require.True(t, ok)
	assert.Equal(t, "Alice Smith", actx.SubjectName)
	assert.ElementsMatch(t, []string{"alice", "devs", "admins"}, actx.Principals)
}

func TestIntegrationRejected(t *testing.T) {
	plain, _ := integrationURLs(t)
	for name, creds := range map[string][2]string{
		"wrong password":  {"alice", "wrong"},
		"empty password":  {"alice", ""},
		"unknown user":    {"mallory", "secret"},
		"filter injected": {"alice)(uid=*", "secret"},
		"empty user":      {"", "secret"},
	} {
		actx, ok := integrationLogin(t, integrationConfig(plain), creds[0], creds[1])
		assert.False(t, ok, name)
		assert.Nil(t, actx, name)
	}
}

// A DN containing characters that are special in search filters, and a
// group name containing a comma.
func TestIntegrationSpecialCharacters(t *testing.T) {
	plain, _ := integrationURLs(t)
	conf := integrationConfig(plain)
	conf.UserBindDN = "uid={{.UserName}},ou=Contractors (EMEA),ou=people,dc=example,dc=com"
	actx, ok := integrationLogin(t, conf, "carol", "secret")
	require.True(t, ok)
	assert.Equal(t, "Carol Jones", actx.SubjectName)
	assert.ElementsMatch(t, []string{"carol", "devs", "Sales, EMEA"}, actx.Principals)
}

func TestIntegrationTLS(t *testing.T) {
	plain, ldaps := integrationURLs(t)
	startTLS := plain + "/?startTLS=true"
	for _, u := range []string{startTLS, ldaps} {
		// The container uses a self-signed certificate
		conf := integrationConfig(u)
		_, ok := integrationLogin(t, conf, "alice", "secret")
		assert.False(t, ok, "%s: untrusted certificate must be rejected", u)

		conf.Insecure = true
		actx, ok := integrationLogin(t, conf, "alice", "secret")
		if assert.True(t, ok, u) {
			assert.Contains(t, actx.Principals, "admins")
		}
	}
}

// Configuration as written in a config file, through the backend factory:
// a userSearchGetAttributes list shorter than the default keeps displayName
// (see config.legacySliceOverlay).
func TestIntegrationConfigFile(t *testing.T) {
	plain, _ := integrationURLs(t)
	yaml := `
itldap:
  serverURL: ` + plain + `
  userBindDN: 'uid={{.UserName}},ou=people,dc=example,dc=com'
  userSearchBase: ou=people,dc=example,dc=com
  userSearchFilter: '(&(objectClass=inetOrgPerson)(uid={{.UserName}}))'
  userSearchGetAttributes: [uid]
  groupSearchBase: ou=groups,dc=example,dc=com
  groupSearchFilter: '(&(objectClass=groupOfNames)(member={{.User.DN}}))'
  subjectNameTemplate: '{{.User.displayName}} ({{.User.uid}})'
  principalTemplate: 'ldap-{{.Group.cn}}'
  principals: [everyone]
  extensions:
    permit-pty: ""
`
	require.NoError(t, config.LoadBytes([]byte(strings.TrimSpace(yaml)+"\n")))
	a, err := factory("itldap")
	require.NoError(t, err)
	actx, ok := a.Authenticate(nil, &auth.Credentials{UserIdentifier: "alice", Secret: []byte("secret"), Meta: map[string]any{}})
	require.True(t, ok)
	assert.Equal(t, "Alice Smith (alice)", actx.SubjectName)
	assert.ElementsMatch(t, []string{"everyone", "alice", "ldap-devs", "ldap-admins"}, actx.Principals)
	assert.Contains(t, actx.Extensions, "permit-pty")
}
