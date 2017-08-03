package authfile

import (
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/auth/backend"
	"github.com/aakso/ssh-inscribe/pkg/config"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var Log *logrus.Entry = logging.GetLogger("authfile").WithField("pkg", "auth/backend/authfile")

const (
	Type         = "authfile"
	DefaultName  = "authfile"
	DefaultRealm = "default realm"
)

func factory(configsection string) (auth.Authenticator, error) {
	config.SetDefault(configsection, Defaults)
	tmpconf, err := config.Get(configsection)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot load configuration from %s for %s", configsection, Type)
	}
	conf, _ := tmpconf.(*Config)
	if conf == nil {
		return nil, errors.Errorf("cannot load configuration from %s for %s", configsection, Type)
	}
	return New(conf)
}

func init() {
	backend.RegisterBackend(Type, factory)
	config.SetDefault(Type, Defaults)
}
