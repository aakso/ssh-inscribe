package authldap

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"text/template"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/aakso/ssh-inscribe/internal/auth"
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
	if creds == nil {
		return nil, false
	}
	log := al.log.WithField("action", "authenticate")
	if v, ok := creds.Meta[auth.MetaAuditID]; ok {
		log = log.WithField(auth.MetaAuditID, v)
	}

	// An empty password turns a simple bind into an unauthenticated bind,
	// which many directory servers report as successful.
	if creds.UserIdentifier == "" || len(creds.Secret) == 0 {
		log.Info("empty username or password")
		return nil, false
	}

	newctx := &auth.AuthContext{
		Status:          auth.StatusCompleted,
		Parent:          pctx,
		SubjectName:     creds.UserIdentifier,
		AuthMeta:        creds.Meta,
		Principals:      append([]string(nil), al.config.Principals...),
		CriticalOptions: al.config.CriticalOptions,
		Extensions:      al.config.Extensions,
		Authenticator:   al.Name(),
	}
	if newctx.AuthMeta == nil {
		newctx.AuthMeta = make(map[string]any)
	}

	// Add username as principal if configured
	if al.config.UserNamePrincipal {
		newctx.Principals = append(newctx.Principals, creds.UserIdentifier)
	}

	// Template context is passed to all templates
	tplCtx := map[string]any{
		"UserName": creds.UserIdentifier,
	}

	conn, err := al.dial()
	if err != nil {
		log.WithError(err).Error("cannot connect to directory server")
		return nil, false
	}
	defer func() {
		_ = conn.Close()
	}()

	binddn := al.RenderTpl(UserBindDN, tplCtx)
	if err := conn.Bind(binddn, string(creds.Secret)); err != nil {
		log.WithError(err).Error("cannot bind")
		return nil, false
	}

	// Find user entry, require a single match
	filter := al.RenderTpl(UserSearchFilter, filterContext(tplCtx))
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
		filter = al.RenderTpl(GroupSearchFilter, filterContext(tplCtx))
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

func (al *AuthLDAP) dial() (*ldap.Conn, error) {
	timeout := time.Second * time.Duration(al.config.Timeout)
	tlsConfig := &tls.Config{
		InsecureSkipVerify: al.config.Insecure, //nolint:gosec // explicit opt-in via configuration
		ServerName:         al.url.Hostname(),
		MinVersion:         tls.VersionTLS12,
	}
	addr := (&url.URL{Scheme: al.url.Scheme, Host: al.url.Host}).String()
	conn, err := ldap.DialURL(addr,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(tlsConfig),
	)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if al.connectMode == ConnectModeStartTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// filterContext returns a copy of the template context where every value
// that may originate from the user or the directory is escaped for use in an
// LDAP search filter (RFC 4515).
func filterContext(tplCtx map[string]any) map[string]any {
	ret := make(map[string]any, len(tplCtx))
	for k, v := range tplCtx {
		ret[k] = escapeFilterValue(v)
	}
	return ret
}

func escapeFilterValue(v any) any {
	switch v := v.(type) {
	case string:
		return ldap.EscapeFilter(v)
	case []string:
		r := make([]string, len(v))
		for i, s := range v {
			r[i] = ldap.EscapeFilter(s)
		}
		return r
	case EntryMap:
		r := make(EntryMap, len(v))
		for k, val := range v {
			r[k] = escapeFilterValue(val)
		}
		return r
	default:
		return v
	}
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

func (al *AuthLDAP) RenderTpl(name string, data any) string {
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
			tplError = fmt.Errorf("cannot parse %s: %w", name, err)
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
		return nil, fmt.Errorf("cannot parse ServerURL: %w", err)
	}
	connectMode := ConnectModePlain
	switch url.Scheme {
	case "ldap":
		if v := url.Query().Get("startTLS"); v != "" {
			// Any value enables StartTLS. Honouring false would silently
			// turn existing encrypted connections into plain text.
			connectMode = ConnectModeStartTLS
			if enabled, err := strconv.ParseBool(v); err == nil && !enabled {
				Log.WithField("name", conf.Name).Warnf("serverURL has startTLS=%s, which enables StartTLS; remove the parameter to connect without TLS", v)
			}
		}
	case "ldaps":
		connectMode = ConnectModeLDAPS
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", url.Scheme)
	}
	if url.Port() == "" {
		return nil, errors.New("missing port for the ServerURL")
	}
	log := Log.WithFields(logrus.Fields{
		"realm": conf.Realm,
		"name":  conf.Name,
	})
	if connectMode == ConnectModePlain {
		log.Warn("LDAP connection is not encrypted, passwords are sent in clear text. Use ldaps:// or ?startTLS=true")
	}
	if conf.Insecure {
		log.Warn("LDAP server certificate verification is disabled")
	}

	return &AuthLDAP{
		log:         log,
		config:      conf,
		url:         url,
		connectMode: connectMode,
		tpls:        rootTpl,
	}, nil
}

type EntryMap map[string]any

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
	ret := make(map[string]any)
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
