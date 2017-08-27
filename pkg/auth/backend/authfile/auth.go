package authfile

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"strings"

	"github.com/ghodss/yaml"

	"golang.org/x/crypto/ssh"

	"golang.org/x/crypto/bcrypt"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type AuthFile struct {
	config *Config
	users  map[string]UserEntry
	log    *logrus.Entry
}

func (fa *AuthFile) Reload() error {
	var tmp struct{ Users []UserEntry }
	data, err := ioutil.ReadFile(fa.config.Path)
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
	switch fa.CredentialType() {
	case auth.CredentialSSHPublicKey:
		return fa.authenticateWithSSHKey(pctx, creds)
	default:
		return fa.authenticateWithPassword(pctx, creds)
	}
}

func (fa *AuthFile) authenticateWithSSHKey(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	log := fa.log.WithField("action", "authenticateWithSSHKey")

	meta := creds.Meta
	if meta == nil {
		meta = map[string]interface{}{}
	}

	if v, ok := meta[auth.MetaAuditID]; ok {
		log = log.WithField(auth.MetaAuditID, v)
	}

	startFlow := func() (*auth.AuthContext, bool) {
		meta[auth.MetaChallenge] = util.RandB64(32)
		return &auth.AuthContext{
			Status:        auth.StatusPending,
			Parent:        pctx,
			Authenticator: fa.Name(),
			AuthMeta:      meta,
		}, true
	}
	completeFlow := func() (*auth.AuthContext, bool) {
		log = log.WithField("user", creds.UserIdentifier)
		entry, ok := fa.users[creds.UserIdentifier]
		if !ok {
			log.Info("user not found")
			return nil, false
		}
		sig := &ssh.Signature{}
		if err := json.Unmarshal(creds.Secret, sig); err != nil {
			log.WithError(err).Error("cannot parse signature")
			return nil, false
		}
		pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(entry.PublicKey))
		if err != nil {
			log.WithError(err).Error("cannot parse public key")
			return nil, false
		}
		if err := pubkey.Verify([]byte(pctx.GetMetaString(auth.MetaChallenge)), sig); err != nil {
			log.WithError(err).Error("signature verify error")
			return nil, false
		}
		pctx.Status = auth.StatusCompleted
		pctx.SubjectName = entry.Name
		pctx.Principals = entry.Principals
		pctx.CriticalOptions = entry.CriticalOptions
		pctx.Extensions = entry.Extensions
		pctx.Authenticator = fa.Name()
		pctx.AuthMeta = meta
		return pctx, true
	}

	if pctx == nil {
		fa.log.Debug("no actx, start new flow")
		return startFlow()
	}

	if pctx.Authenticator == fa.Name() {
		fa.log.Debug("completing flow")
		return completeFlow()
	}

	fa.log.Debug("mfa, starting new flow")
	return startFlow()

}

func (fa *AuthFile) authenticateWithPassword(pctx *auth.AuthContext, creds *auth.Credentials) (*auth.AuthContext, bool) {
	log := fa.log.WithField("action", "authenticateWithPassword")

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
		if err := bcrypt.CompareHashAndPassword([]byte(entry.Password), []byte(creds.Secret)); err != nil {
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
	switch strings.ToLower(fa.config.CredentialType) {
	case "sshkey":
		return auth.CredentialSSHPublicKey
	default:
		return auth.CredentialUserPassword
	}
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
	switch strings.ToLower(config.CredentialType) {
	case "password", "sshkey":
		break
	default:
		return nil, errors.New("invalid value for credentialType")
	}
	if err := r.Reload(); err != nil {
		return r, err
	}
	return r, nil
}

type UserEntry struct {
	Name            string
	Password        string
	PublicKey       string
	Principals      []string
	CriticalOptions map[string]string
	Extensions      map[string]string
}
