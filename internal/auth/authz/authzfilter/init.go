package authzfilter

import (
	"github.com/sirupsen/logrus"

	"github.com/aakso/ssh-inscribe/internal/logging"
)

var Log *logrus.Entry = logging.GetLogger("authzfilter").WithField("pkg", "auth/authz/authzfilter")
