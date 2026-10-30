//go:build !race

package authldap

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/vjeantet/ldapserver"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/logging"
)

var (
	testConf   = *Defaults
	testServer *ldapserver.Server
	testLog    = logging.GetLogger("test")
	verbose    bool
)

func initServer() {
	testConf.UserSearchBase = "cn=users,dc=example,dc=com"
	testConf.GroupSearchBase = "cn=groups,dc=example,dc=com"
	// ldapserver cannot parse the default search filter for some resason. Use more simple one
	testConf.GroupSearchFilter = "(&(objectClass=group)(member={{.User.DN}}))"
	var logger logrus.StdLogger
	if verbose {
		logger = testLog.WithField("component", "testLDAPServer")
	} else {
		logger = &logrus.Logger{Out: io.Discard}
	}
	testServer = newTestServer(logger)
	time.Sleep(50 * time.Millisecond)
	// This causes race detector to freak out. Unfortunately no way to fix it with dynamic port selection
	testConf.ServerURL = "ldap://" + testServer.Listener.Addr().String()
	testConf.UserBindDN = "{{.UserName}}"
}

func TestMain(m *testing.M) {
	for _, v := range os.Args {
		if strings.EqualFold(v, "-test.v=true") {
			verbose = true
			logging.SetLevel(logrus.DebugLevel)
		}
	}
	initServer()
	ret := m.Run()
	testServer.Stop()
	os.Exit(ret)
}

// newTestInstance returns an authenticator for the test directory using a
// copy of testConf, so tests can change settings independently.
func newTestInstance(t *testing.T, mods ...func(*Config)) *AuthLDAP {
	t.Helper()
	conf := testConf
	for _, m := range mods {
		m(&conf)
	}
	inst, err := New(&conf)
	if err != nil {
		t.Fatal(err)
	}
	// The mock directory cannot answer WhoAmI, answer like AD does.
	inst.whoAmI = func(*ldap.Conn) (string, error) { return `u:TEST\` + TestUser, nil }
	return inst
}

func login(inst *AuthLDAP) (*auth.AuthContext, bool) {
	return inst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte(TestPassword),
	})
}

func TestAuthenticate(t *testing.T) {
	assert := assert.New(t)
	actx, ok := newTestInstance(t).Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte(TestPassword),
	})
	assert.True(ok)
	assert.NotNil(actx)
	assert.Equal(TestUserCN, actx.SubjectName)
	assert.Contains(actx.Principals, TestGroupCN1)
	assert.Contains(actx.Principals, TestGroupCN2)
	assert.Contains(actx.Principals, TestUser)
}

func TestAuthenticateNoUserNamePrincipal(t *testing.T) {
	inst := newTestInstance(t, func(c *Config) { c.UserNamePrincipal = false })
	assert := assert.New(t)
	actx, ok := inst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte(TestPassword),
	})
	assert.True(ok)
	assert.NotNil(actx)
	assert.NotContains(actx.Principals, TestUser)
}

func TestAuthFail(t *testing.T) {
	assert := assert.New(t)
	actx, ok := newTestInstance(t).Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte("invalid"),
	})
	assert.False(ok)
	assert.Nil(actx)
}

func TestAuthEmptyPassword(t *testing.T) {
	assert := assert.New(t)
	actx, ok := newTestInstance(t).Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         nil,
	})
	assert.False(ok, "empty password must not result in an unauthenticated bind")
	assert.Nil(actx)
}

func TestSearchFilterEscaping(t *testing.T) {
	assert := assert.New(t)
	inst := newTestInstance(t)
	tplCtx := map[string]any{
		"UserName": "alice)(sAMAccountName=*",
		"User": EntryMap{
			"dn": []string{"CN=Smith\\, John (ext),OU=Users,DC=example,DC=com"},
		},
	}
	userFilter := inst.RenderTpl(UserSearchFilter, filterContext(tplCtx))
	assert.Equal(`(&(objectClass=user)(sAMAccountName=alice\29\28sAMAccountName=\2a))`, userFilter)

	groupFilter := inst.RenderTpl(GroupSearchFilter, filterContext(tplCtx))
	assert.Equal(`(&(objectClass=group)(member=CN=Smith\5c, John \28ext\29,OU=Users,DC=example,DC=com))`, groupFilter)

	// Other templates get the raw values
	assert.Equal("alice)(sAMAccountName=*", inst.RenderTpl(UserBindDN, tplCtx))
}

func TestUserNamePrincipalAttribute(t *testing.T) {
	inst := newTestInstance(t, func(c *Config) { c.UserNamePrincipalAttribute = "samaccountname" })
	actx, ok := login(inst)
	if assert.True(t, ok) {
		assert.Contains(t, actx.Principals, TestUserAccountName)
		assert.NotContains(t, actx.Principals, TestUser, "the typed name must not be used")
	}

	for _, attr := range []string{"uid", "noSuchAttribute"} {
		inst := newTestInstance(t, func(c *Config) { c.UserNamePrincipalAttribute = attr })
		actx, ok := login(inst)
		assert.False(t, ok, "%s: a multi-valued or missing attribute must refuse the login", attr)
		assert.Nil(t, actx)
	}

	inst = newTestInstance(t, func(c *Config) {
		c.UserNamePrincipal = false
		c.UserNamePrincipalAttribute = "noSuchAttribute"
	})
	actx, ok = login(inst)
	if assert.True(t, ok, "the attribute is not needed without userNamePrincipal") {
		assert.NotContains(t, actx.Principals, TestUser)
	}
}

// The bind and the user search are configured with separate templates. The
// login must fail when they find different entries.
func TestVerifyBoundIdentity(t *testing.T) {
	for _, tc := range []struct {
		authzID string
		err     error
		ok      bool
	}{
		{authzID: "dn:CN=test user,CN=Users,DC=example,DC=com", ok: true},
		{authzID: `u:TEST\TESTUSER`, ok: true},
		{authzID: "u:testuser", ok: true},
		{authzID: "dn:cn=Other User,cn=users,dc=example,dc=com"},
		{authzID: `u:TEST\mallory`},
		{authzID: "dn:"},
		{authzID: ""},
		{authzID: "x:testuser"},
		{err: errors.New("unwilling to perform")},
	} {
		inst := newTestInstance(t)
		inst.whoAmI = func(*ldap.Conn) (string, error) { return tc.authzID, tc.err }
		actx, ok := login(inst)
		assert.Equal(t, tc.ok, ok, "%q", tc.authzID)
		assert.Equal(t, tc.ok, actx != nil, "%q", tc.authzID)
	}

	inst := newTestInstance(t, func(c *Config) { c.VerifyBoundIdentity = false })
	inst.whoAmI = func(*ldap.Conn) (string, error) {
		t.Error("WhoAmI must not be called when the check is disabled")
		return "", nil
	}
	_, ok := login(inst)
	assert.True(t, ok)
}

// The test directory does not implement StartTLS. Requiring it must fail the
// login instead of falling back to plain text.
func TestStartTLSIsEnforced(t *testing.T) {
	conf := testConf
	conf.ServerURL = testConf.ServerURL + "/?startTLS=true"
	inst, err := New(&conf)
	if !assert.NoError(t, err) {
		return
	}
	actx, ok := inst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte(TestPassword),
	})
	assert.False(t, ok)
	assert.Nil(t, actx)
}
