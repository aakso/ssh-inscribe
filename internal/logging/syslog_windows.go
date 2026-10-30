package logging

import (
	"errors"

	"github.com/sirupsen/logrus"
)

func getSyslogLoggerHook(_ string) (logrus.Hook, error) {
	return nil, errors.New("no syslog available on Windows")
}
