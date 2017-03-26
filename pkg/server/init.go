package server

import "github.com/aakso/ssh-inscribe/pkg/config"
import "github.com/aakso/ssh-inscribe/pkg/logging"

var Log = logging.GetLogger("server").WithField("pkg", "server")

func init() {
	config.SetDefault("server", Defaults)
}
