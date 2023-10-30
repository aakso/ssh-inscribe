package logging

import "github.com/aakso/ssh-inscribe/internal/config"

func init() {
	config.SetDefault("logging", Defaults)
}
