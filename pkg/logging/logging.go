package logging

import (
	"fmt"
	"io/ioutil"
	"log/syslog"
	"net/url"
	"strings"

	"github.com/Sirupsen/logrus"
	syslog2 "github.com/Sirupsen/logrus/hooks/syslog"
	"github.com/aakso/ssh-inscribe/pkg/config"
	"github.com/pkg/errors"
)

var pkgLoggers map[string]*logrus.Logger = make(map[string]*logrus.Logger)

// Initialize package level logger. This function should only be called in package initialization
func GetLogger(name string) *logrus.Logger {
	logger, found := pkgLoggers[name]
	if found {
		return logger
	}
	logger = logrus.New()
	pkgLoggers[name] = logger
	return logger
}

func SetLevel(level logrus.Level) {
	setLevel("", level)
}

func setLevel(pkg string, level logrus.Level) {
	for k, logger := range pkgLoggers {
		if k == pkg || pkg == "" {
			logger.Level = level
		}
	}
}

func Setup() error {
	var (
		level     logrus.Level
		formatter logrus.Formatter
		err       error
	)
	tmp, err := config.Get("logging")
	if err != nil {
		return errors.Wrap(err, "cannot initialize logging")
	}
	conf, _ := tmp.(*Config)
	if conf == nil {
		return errors.New("cannot initialize logging")

	}

	if !conf.EnableConsole {
		logrus.SetOutput(ioutil.Discard)
		for _, logger := range pkgLoggers {
			logger.Out = ioutil.Discard
		}
	}

	if conf.EnableSyslog {
		var dst, scheme string
		if conf.SyslogURL != "" {
			surl, err := url.Parse(conf.SyslogURL)
			if err != nil {
				return errors.Wrap(err, "cannot parse syslogURL")
			}
			scheme = surl.Scheme
			dst = fmt.Sprintf("%s:%s", surl.Hostname(), surl.Port())
		}
		hook, err := syslog2.NewSyslogHook(scheme, dst, syslog.LOG_INFO, "")
		if err != nil {
			return errors.Wrap(err, "cannot create syslog hook")
		}
		logrus.AddHook(hook)
		for _, logger := range pkgLoggers {
			logger.Hooks.Add(hook)
		}
	}

	level, err = logrus.ParseLevel(strings.ToLower(conf.DefaultLevel))
	if err != nil {
		return errors.Errorf("unknown log level: %q, available: panic, fatal, error, warn, info, debug", conf.DefaultLevel)
	}

	switch strings.ToLower(conf.Format) {
	case "text":
		formatter = new(logrus.TextFormatter)
	case "json":
		formatter = new(logrus.JSONFormatter)
	default:
		return errors.Errorf("unknown log formatter: %q, available: text, json", conf.Format)
	}

	for _, v := range pkgLoggers {
		v.Level = level
		v.Formatter = formatter
	}

	if len(conf.PackageLevel) > 0 {
		pkgs := []string{}
		for k, _ := range pkgLoggers {
			pkgs = append(pkgs, k)
		}
		for setpkg, setlevel := range conf.PackageLevel {
			logger, found := pkgLoggers[setpkg]
			if !found {
				return errors.Errorf("unknown package, available: %s", strings.Join(pkgs, ", "))
			}
			level, err := logrus.ParseLevel(strings.ToLower(setlevel))
			if err != nil {
				return errors.Errorf("unknown log level: %q, available: panic, fatal, error, warn, info, debug", setlevel)
			}
			logger.Level = level
		}
	}

	return nil
}
