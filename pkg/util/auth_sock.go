// +build !windows

package util

import (
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
)

func DialAuthSock(name string) (net.Conn, error) {
	if name == "" {
		name = os.Getenv("SSH_AUTH_SOCK")
	}
	conn, err := net.Dial("unix", name)
	if err != nil {
		return nil, errors.Wrap(err, "could not connect to ssh-agent")
	}
	return conn, nil
}

func LocalListen(name string) (net.Listener, error) {
	if _, err := os.Stat(name); err == nil {
		if err := os.Remove(name); err != nil {
			return nil, errors.Wrapf(err, "cannot remove existing socket: %s", name)
		}
	}
	prevUmask := syscall.Umask(0177)
	defer syscall.Umask(prevUmask)
	ln, err := net.Listen("unix", name)
	if err != nil {
		return nil, errors.Wrap(err, "could not create a unix listener socket")
	}
	return ln, nil
}
