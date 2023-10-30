package server

import (
	"github.com/aakso/ssh-inscribe/internal/config"
	"github.com/aakso/ssh-inscribe/internal/logging"
)

var Log = logging.GetLogger("server").WithField("pkg", "server")

func init() {
	config.SetDefault("server", Defaults)
}
