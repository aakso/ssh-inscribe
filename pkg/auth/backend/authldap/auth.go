package authldap

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/url"
	"text/template"
	"time"

	ldap "gopkg.in/ldap.v2"

	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/pkg/errors"
)

const (
	ConnectModePlain int = iota
	ConnectModeLDAPS
	ConnectModeStartTLS

	UserBindDN        = "UserBindDN"
	UserSearchFilter  = "UserSearchFilter"
	GroupSearchFilter = "GroupSearchFilter"
	SubjectName       = "SubjectName"
	Principal         = "Principal"

	AuthLDAPUsertEntry = "authLDAPUserEntry"
)

type AuthLDAP struct {
	log         *logrus.Entry
	config      *Config
	url         *url.URL
	connectMode int

	tpls *template.Template
}

func (al *AuthLDAP) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	var err error
	log := al.log.WithField("action", "authenticate")
	if v, ok := creds.Meta[auth.MetaAuditID]; ok {
		log = log.WithField(auth.MetaAuditID, v)
	}

	if creds == nil {
		return nil, false
	}

	newctx := &auth.AuthContext{
		Parent:          pctx,
		SubjectName:     creds.UserIdentifier,
		AuthMeta:        creds.Meta,
		Principals:      al.config.Principals,
		CriticalOptions: al.config.CriticalOptions,
		Extensions:      al.config.Extensions,
		Authenticator:   al.Name(),
	}
	if newctx.AuthMeta == nil {
		newctx.AuthMeta = make(map[string]interface{})
	}
	tplCtx := map[string]interface{}{
		"UserName": creds.UserIdentifier,
	}

	// Set ldap package level dial timeout as it doesn't offer any other way
	ldap.DefaultTimeout = time.Second * time.Duration(al.config.Timeout)
	var conn *ldap.Conn
	host := fmt.Sprintf("%s:%s", al.url.Hostname(), al.url.Port())
	switch al.connectMode {
	case ConnectModeLDAPS:
		conn, err = ldap.DialTLS("tcp", host, &tls.Config{
			InsecureSkipVerify: al.config.Insecure,
			ServerName:         al.url.Hostname(),
		})
		if err != nil {
			log.WithError(err).Error("cannot connect to directory server")
			return nil, false
		}
	case ConnectModePlain, ConnectModeStartTLS:
		conn, err = ldap.Dial("tcp", host)
		if err != nil {
			log.WithError(err).Error("cannot connect to directory server")
			return nil, false
		}
	}
	defer conn.Close()
	conn.SetTimeout(time.Second * time.Duration(al.config.Timeout))
	if al.connectMode == ConnectModeStartTLS {
		if err := conn.StartTLS(&tls.Config{
			InsecureSkipVerify: al.config.Insecure,
			ServerName:         al.url.Hostname(),
		}); err != nil {
			log.WithError(err).Error("cannot connect to directory server")
			return nil, false
		}
	}

	binddn := al.RenderTpl(UserBindDN, tplCtx)
	if err := conn.Bind(binddn, string(creds.Secret)); err != nil {
		log.WithError(err).Error("cannot bind")
		return nil, false
	}

	// Find user entry, require a single match
	filter := al.RenderTpl(UserSearchFilter, tplCtx)
	res, err := al.search(conn, al.config.UserSearchBase, filter, al.config.UserSearchGetAttributes)
	if err != nil {
		log.WithError(err).Error("search failure")
		return nil, false
	}
	if len(res.Entries) != 1 {
		log.WithField("matches", len(res.Entries)).Error("not a single match")
		return nil, false
	}
	user := entryToMap(res.Entries[0])
	tplCtx["User"] = user
	newctx.SubjectName = al.RenderTpl(SubjectName, tplCtx)
	newctx.AuthMeta[AuthLDAPUsertEntry] = user
	log.WithField("user", user["cn"]).Debug("user search ok")

	// Find groups
	if al.config.AddPrincipalsFromGroups {
		filter = al.RenderTpl(GroupSearchFilter, tplCtx)
		res, err = al.search(conn, al.config.GroupSearchBase, filter, al.config.GroupSearchGetAttributes)
		if err != nil {
			log.WithError(err).Error("search failure")
			return nil, false
		}
		for _, entry := range res.Entries {
			group := entryToMap(entry)
			log.WithField("group", group["cn"]).Debug("searched group")
			tplCtx["Group"] = group
			if principal := al.RenderTpl(Principal, tplCtx); principal != "" {
				newctx.Principals = append(newctx.Principals, principal)
			}
		}
	}

	return newctx, true
}

func (al *AuthLDAP) search(conn *ldap.Conn, base, filter string, attrs []string) (*ldap.SearchResult, error) {
	al.log.WithFields(logrus.Fields{
		"base":   base,
		"filter": filter,
		"attrs":  attrs,
	}).Debug("search")
	sr := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.DerefInSearching,
		0, 0, false,
		filter,
		attrs,
		nil,
	)
	return conn.Search(sr)
}

func (al *AuthLDAP) RenderTpl(name string, data interface{}) string {
	buf := bytes.NewBuffer([]byte{})
	err := al.tpls.ExecuteTemplate(buf, name, data)
	if err != nil {
		al.log.WithError(err).Errorf("template render error: %s", name)
	}
	return buf.String()
}

func (al *AuthLDAP) Type() string {
	return Type
}

func (al *AuthLDAP) Name() string {
	return al.config.Name
}

func (al *AuthLDAP) Realm() string {
	return al.config.Realm
}

func (al *AuthLDAP) CredentialType() string {
	return auth.CredentialUserPassword
}

func New(conf *Config) (*AuthLDAP, error) {
	if conf == nil {
		conf = Defaults
	}

	var tplError error
	rootTpl := template.New("root")
	parseTpl := func(name, tpl string) {
		_, err := rootTpl.New(name).Parse(tpl)
		if err != nil {
			tplError = errors.Wrapf(err, "cannot parse %s", name)
		}
	}
	parseTpl(UserBindDN, conf.UserBindDN)
	parseTpl(UserSearchFilter, conf.UserSearchFilter)
	parseTpl(GroupSearchFilter, conf.GroupSearchFilter)
	parseTpl(SubjectName, conf.SubjectNameTemplate)
	parseTpl(Principal, conf.PrincipalTemplate)
	if tplError != nil {
		return nil, tplError
	}

	url, err := url.Parse(conf.ServerURL)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse ServerURL")
	}
	connectMode := ConnectModePlain
	switch url.Scheme {
	case "ldap":
		if url.Query().Get("startTLS") != "" {
			connectMode = ConnectModeStartTLS
		}
	case "ldaps":
		connectMode = ConnectModeLDAPS
	default:
		return nil, errors.Errorf("unsupported scheme: %s", url.Scheme)
	}
	if url.Port() == "" {
		return nil, errors.New("missing port for the ServerURL")
	}

	return &AuthLDAP{
		log:         Log.WithField("realm", conf.Realm),
		config:      conf,
		url:         url,
		connectMode: connectMode,
		tpls:        rootTpl,
	}, nil
}

type EntryMap map[string]interface{}

func (em EntryMap) DN() string {
	return em.Get("dn")
}

func (em EntryMap) Get(k string) string {
	switch v := em[k].(type) {
	case []string:
		if len(v) >= 1 {
			return v[0]
		}
	case string:
		return v
	}
	return ""
}

func entryToMap(entry *ldap.Entry) EntryMap {
	ret := make(map[string]interface{})
	ret["dn"] = []string{entry.DN}
	for _, v := range entry.Attributes {
		if len(v.Values) == 1 {
			ret[v.Name] = v.Values[0]
		} else {
			ret[v.Name] = v.Values
		}
	}
	return EntryMap(ret)
}
