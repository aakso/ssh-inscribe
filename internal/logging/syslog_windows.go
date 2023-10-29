package logging

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func getSyslogLoggerHook(syslogURL string) (logrus.Hook, error) {
	return nil, errors.New("no syslog available on Windows")
}
