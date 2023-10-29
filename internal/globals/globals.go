package globals

import (
	"os"
	"path"

	"github.com/blang/semver/v4"
)

// Override thru linker -X flag if needed
var (
	varDir  = ""
	confDir = ""
	version = "0.0.0-snapshot"
)

const (
	ClientUserAgent = "ssh-inscribe"
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

func Version() semver.Version {
	return semver.MustParse(version)
}

func IsSnapshotVersion(ver semver.Version) bool {
	return len(ver.Pre) > 0
}
