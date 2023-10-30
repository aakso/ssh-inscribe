package logging

type Config struct {
	DefaultLevel  string            `yaml:"defaultLevel"`
	PackageLevel  map[string]string `yaml:"packageLevel"`
	Format        string
	EnableConsole bool   `yaml:"enableConsole"`
	EnableSyslog  bool   `yaml:"enableSyslog"`
	SyslogURL     string `yaml:"syslogURL"`
}

var Defaults = &Config{
	DefaultLevel:  "info",
	PackageLevel:  map[string]string{},
	Format:        "text",
	EnableConsole: true,
	EnableSyslog:  false,
	SyslogURL:     "",
}
