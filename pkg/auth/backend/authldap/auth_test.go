// +build !race

package authldap

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/vjeantet/ldapserver"
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
		logger = &logrus.Logger{Out: ioutil.Discard}
	}
	testServer = newTestServer(logger)
	time.Sleep(50 * time.Millisecond)
	// This causes race detector to freak out. Unfortunately no way to fix it with dynamic port selection
	testConf.ServerURL = fmt.Sprintf("ldap://%s", testServer.Listener.Addr().String())
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
