//+build !windows

package logging

import (
	"fmt"
	"log/syslog"
	"net/url"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	syslog2 "github.com/sirupsen/logrus/hooks/syslog"
)

func getSyslogLoggerHook(syslogURL string) (logrus.Hook, error) {
	var dst, scheme string
	surl, err := url.Parse(syslogURL)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse syslogURL")
	}
	scheme = surl.Scheme
	dst = fmt.Sprintf("%s:%s", surl.Hostname(), surl.Port())
	hook, err := syslog2.NewSyslogHook(scheme, dst, syslog.LOG_INFO, "")
	if err != nil {
		return nil, errors.Wrap(err, "cannot create syslog hook")
	}
	return hook, nil
}
