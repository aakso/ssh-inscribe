package keysigner

import (
	"github.com/sirupsen/logrus"

	"github.com/aakso/ssh-inscribe/internal/logging"
)

var Log *logrus.Entry = logging.GetLogger("keysigner").WithField("pkg", "keysigner")
