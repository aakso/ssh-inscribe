//+build !race

package authldap

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/vjeantet/ldapserver"
)

const (
	TestUser     = "testuser"
	TestUserCN   = "Test User"
	TestPassword = "testpassword"
	TestGroupCN1 = "Test Group 1"
	TestGroupCN2 = "Test Group 2"
)

func newTestServer(logger logrus.StdLogger) *ldapserver.Server {
	ldapserver.Logger = logger

	server := ldapserver.NewServer()

	routes := ldapserver.NewRouteMux()
	routes.Bind(handleBind)
	fmt.Println(testConf.UserSearchBase)
	routes.Search(handleUserSearch).
		BaseDn(testConf.UserSearchBase).
		Label("SearchUser")
	routes.Search(handleGroupSearch).
		BaseDn(testConf.GroupSearchBase).
		Label("SearchGroups")
	server.Handle(routes)

	go func() {
		if err := server.ListenAndServe("127.0.0.1:0"); err != nil {
			logger.Fatalf("listen and serve: %v", err)
		}
	}()
	return server
}

func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)

	if string(r.Name()) == TestUser && string(r.AuthenticationSimple()) == TestPassword {
		w.Write(res)
		return
	}

	res.SetResultCode(ldapserver.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("auth failed")
	w.Write(res)
}

func handleUserSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)

	if !strings.Contains(r.FilterString(), TestUser) {
		res.SetResultCode(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	e := ldapserver.NewSearchResultEntry("cn=" + TestUserCN + "," + string(r.BaseObject()))
	e.AddAttribute("displayName", "Test User")
	e.AddAttribute("cn", TestUserCN)
	e.AddAttribute("objectClass", "user")
	w.Write(e)
	w.Write(res)
}

func handleGroupSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)

	if !strings.Contains(r.FilterString(), TestUserCN) {
		res.SetResultCode(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	e := ldapserver.NewSearchResultEntry("cn=" + TestGroupCN1 + "," + string(r.BaseObject()))
	e.AddAttribute("cn", TestGroupCN1)
	e.AddAttribute("objectClass", "group")
	w.Write(e)

	e = ldapserver.NewSearchResultEntry("cn=" + TestGroupCN2 + "," + string(r.BaseObject()))
	e.AddAttribute("cn", TestGroupCN2)
	e.AddAttribute("objectClass", "group")
	w.Write(e)
	w.Write(res)
}
