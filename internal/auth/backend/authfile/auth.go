package authfile

import (
	"crypto/subtle"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	yaml "gopkg.in/yaml.v2"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

type AuthFile struct {
	config *Config
	users  map[string]UserEntry
	log    *logrus.Entry
}

func (fa *AuthFile) Reload() error {
	var tmp struct{ Users []UserEntry }
	data, err := os.ReadFile(fa.config.Path)
	if err != nil {
		return fmt.Errorf("cannot parse users file: %w", err)
	}
	err = yaml.Unmarshal(data, &tmp)
	if err != nil {
		return fmt.Errorf("cannot parse users file: %w", err)
	}
	for _, e := range tmp.Users {
		if e.Password == "" {
			fa.log.WithField("user", e.Name).Warn("user has no password set, login disabled")
		}
		fa.users[e.Name] = e
	}
	fa.log.WithField("count_users", len(fa.users)).Info("reloaded users")
	return nil
}

func (fa *AuthFile) Authenticate(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	if creds == nil {
		return nil, false
	}
	log := fa.log.WithField("action", "authenticate")

	if v, ok := creds.Meta[auth.MetaAuditID]; ok {
		log = log.WithField(auth.MetaAuditID, v)
	}

	entry, ok := fa.users[creds.UserIdentifier]
	if !ok {
		// Spend the same time as for an existing user so that response
		// times do not reveal which user names exist.
		_ = bcrypt.CompareHashAndPassword(dummyHash, creds.Secret)
		log.WithField("user", creds.UserIdentifier).Info("user not found")
		return nil, false
	}
	if entry.Password == "" || len(creds.Secret) == 0 {
		log.WithField("user", creds.UserIdentifier).Info("empty password")
		return nil, false
	}

	if n, _ := bcrypt.Cost([]byte(entry.Password)); n > 0 {
		log.WithField("user", creds.UserIdentifier).Debug("brypt auth")
		if err := bcrypt.CompareHashAndPassword([]byte(entry.Password), creds.Secret); err != nil {
			log.WithField("user", creds.UserIdentifier).Debug("brypt auth fail")
			return nil, false
		}
		log.WithField("user", creds.UserIdentifier).Debug("brypt auth successful")
	} else {
		log.WithField("user", creds.UserIdentifier).Warn("plain password auth")
		if subtle.ConstantTimeCompare([]byte(entry.Password), creds.Secret) != 1 {
			log.WithField("user", creds.UserIdentifier).Warn("plain password auth fail")
			return nil, false
		}
		log.WithField("user", creds.UserIdentifier).Debug("plain password auth successful")
	}
	return &auth.AuthContext{
		Status:          auth.StatusCompleted,
		Parent:          pctx,
		SubjectName:     entry.Name,
		Principals:      entry.Principals,
		CriticalOptions: entry.criticalOptions(),
		Extensions:      entry.Extensions,
		Authenticator:   fa.Name(),
		AuthMeta:        creds.Meta,
	}, true
}

func (fa *AuthFile) Type() string {
	return Type
}

func (fa *AuthFile) Name() string {
	return fa.config.Name
}

func (fa *AuthFile) Realm() string {
	return fa.config.Realm
}

func (fa *AuthFile) CredentialType() string {
	return auth.CredentialUserPassword
}

func New(config *Config) (*AuthFile, error) {
	r := &AuthFile{
		config: config,
		users:  make(map[string]UserEntry),
		log: Log.WithFields(logrus.Fields{
			"realm": config.Realm,
			"name":  config.Name,
		}),
	}
	if err := r.Reload(); err != nil {
		return r, err
	}
	return r, nil
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy password"), bcrypt.DefaultCost)

type UserEntry struct {
	Name       string
	Password   string
	Principals []string
	// CriticalOptions is the documented key. Without the tag yaml.v2 only
	// matched "criticaloptions" and silently ignored the documented
	// spelling; accept both.
	CriticalOptions      map[string]string `yaml:"criticalOptions"`
	CriticalOptionsLower map[string]string `yaml:"criticaloptions"`
	Extensions           map[string]string
}

func (e UserEntry) criticalOptions() map[string]string {
	if len(e.CriticalOptionsLower) == 0 {
		return e.CriticalOptions
	}
	r := make(map[string]string, len(e.CriticalOptions)+len(e.CriticalOptionsLower))
	for k, v := range e.CriticalOptionsLower {
		r[k] = v
	}
	for k, v := range e.CriticalOptions {
		r[k] = v
	}
	return r
}
