package authfile

import (
	"os"
	"path"
)

type Config struct {
	Name  string
	Realm string
	Path  string
}

var Defaults *Config = &Config{
	Name:  DefaultName,
	Realm: DefaultRealm,
	Path:  path.Join(os.Getenv("HOME"), ".ssh_inscribe", "auth_users.yaml"),
}
