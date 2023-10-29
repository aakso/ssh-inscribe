package authfile

import (
	"bytes"
	"os"

	yaml "gopkg.in/yaml.v2"

	"golang.org/x/crypto/bcrypt"

	"github.com/sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/pkg/errors"
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
		return errors.Wrap(err, "cannot parse users file")
	}
	err = yaml.Unmarshal(data, &tmp)
	if err != nil {
		return errors.Wrap(err, "cannot parse users file")
	}
	for _, e := range tmp.Users {
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
		log.WithField("user", creds.UserIdentifier).Info("user not found")
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
		if !bytes.Equal([]byte(entry.Password), creds.Secret) {
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
		CriticalOptions: entry.CriticalOptions,
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

type UserEntry struct {
	Name            string
	Password        string
	Principals      []string
	CriticalOptions map[string]string
	Extensions      map[string]string
}
