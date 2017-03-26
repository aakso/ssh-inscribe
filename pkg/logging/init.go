package logging

import "github.com/aakso/ssh-inscribe/pkg/config"

func init() {
	config.SetDefault("logging", Defaults)
}
