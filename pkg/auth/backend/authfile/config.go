package authfile

import (
	"path"

	"github.com/aakso/ssh-inscribe/pkg/globals"
)

type Config struct {
	Name  string
	Realm string
	Path  string
}

var Defaults *Config = &Config{
	Name:  DefaultName,
	Realm: DefaultRealm,
	Path:  path.Join(globals.ConfDir(), "auth_users.yaml"),
}
