//go:build !windows

package logging

import (
	"fmt"
	"log/syslog"
	"net/url"

	"github.com/sirupsen/logrus"
	syslog2 "github.com/sirupsen/logrus/hooks/syslog"
)

func getSyslogLoggerHook(syslogURL string) (logrus.Hook, error) {
	var dst, scheme string
	surl, err := url.Parse(syslogURL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse syslogURL: %w", err)
	}
	scheme = surl.Scheme
	dst = fmt.Sprintf("%s:%s", surl.Hostname(), surl.Port())
	hook, err := syslog2.NewSyslogHook(scheme, dst, syslog.LOG_INFO, "")
	if err != nil {
		return nil, fmt.Errorf("cannot create syslog hook: %w", err)
	}
	return hook, nil
}
