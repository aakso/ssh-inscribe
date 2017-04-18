package globals

import (
	"os"
	"path"
)

// Override thru linker -X flag if needed
var (
	varDir  = ""
	confDir = ""
)

func VarDir() string {
	if varDir == "" {
		return os.TempDir()
	}
	return varDir
}

func ConfDir() string {
	if confDir == "" {
		return path.Join(os.Getenv("HOME"), ".ssh_inscribe")
	}
	return confDir
}
