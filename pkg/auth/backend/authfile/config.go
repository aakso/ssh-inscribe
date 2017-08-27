package authfile

import (
	"path"

	"github.com/aakso/ssh-inscribe/pkg/globals"
)

type Config struct {
	Name  string
	Realm string
	Path  string

	// Valid values: password, sshkey
	CredentialType string `yaml:"credentialType"`
}

var Defaults *Config = &Config{
	Name:           DefaultName,
	Realm:          DefaultRealm,
	Path:           path.Join(globals.ConfDir(), "auth_users.yaml"),
	CredentialType: "password",
}
