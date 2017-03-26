package client

import (
	"github.com/aakso/ssh-inscribe/pkg/logging"
)

var Log = logging.GetLogger("client").WithField("pkg", "client")
