//go:build !race

package authldap

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/vjeantet/ldapserver"

	"github.com/aakso/ssh-inscribe/internal/auth"
	"github.com/aakso/ssh-inscribe/internal/logging"
)

var (
	testConf   = *Defaults
	testInst   *AuthLDAP
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

func TestInit(t *testing.T) {
	var err error
	assert := assert.New(t)
	testInst, err = New(&testConf)
	assert.NoError(err)
}

func TestAuthenticate(t *testing.T) {
	assert := assert.New(t)
	actx, ok := testInst.Authenticate(nil, &auth.Credentials{
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
	testInst.config.UserNamePrincipal = false
	assert := assert.New(t)
	actx, ok := testInst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte(TestPassword),
	})
	assert.True(ok)
	assert.NotNil(actx)
	assert.NotContains(actx.Principals, TestUser)
}

func TestAuthFail(t *testing.T) {
	assert := assert.New(t)
	actx, ok := testInst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         []byte("invalid"),
	})
	assert.False(ok)
	assert.Nil(actx)
}

func TestAuthEmptyPassword(t *testing.T) {
	assert := assert.New(t)
	actx, ok := testInst.Authenticate(nil, &auth.Credentials{
		UserIdentifier: TestUser,
		Secret:         nil,
	})
	assert.False(ok, "empty password must not result in an unauthenticated bind")
	assert.Nil(actx)
}

func TestSearchFilterEscaping(t *testing.T) {
	assert := assert.New(t)
	inst, err := New(&testConf)
	if !assert.NoError(err) {
		return
	}
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
