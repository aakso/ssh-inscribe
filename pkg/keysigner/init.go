package keysigner

import (
	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/logging"
)

var Log *logrus.Entry = logging.GetLogger("keysigner").WithField("pkg", "keysigner")
