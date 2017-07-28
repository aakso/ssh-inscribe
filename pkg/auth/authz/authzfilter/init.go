package authzfilter

import (
	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/logging"
)

var Log *logrus.Entry = logging.GetLogger("authzfilter").WithField("pkg", "auth/authz/authzfilter")
