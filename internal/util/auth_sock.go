//go:build !windows
// +build !windows

package util

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

func DialAuthSock(name string) (net.Conn, error) {
	if name == "" {
		name = os.Getenv("SSH_AUTH_SOCK")
	}
	conn, err := net.Dial("unix", name)
	if err != nil {
		return nil, fmt.Errorf("could not connect to ssh-agent: %w", err)
	}
	return conn, nil
}

func LocalListen(name string) (net.Listener, error) {
	if _, err := os.Stat(name); err == nil {
		if err := os.Remove(name); err != nil {
			return nil, fmt.Errorf("cannot remove existing socket: %s: %w", name, err)
		}
	}
	prevUmask := syscall.Umask(0177)
	defer syscall.Umask(prevUmask)
	ln, err := net.Listen("unix", name)
	if err != nil {
		return nil, fmt.Errorf("could not create a unix listener socket: %w", err)
	}
	return ln, nil
}

// CheckSocketPath verifies that name is a unix socket that another local
// user could not have planted. A socket (or a symlink to one) owned by
// someone other than the current user or root is refused when it lives in a
// world-writable directory such as /tmp.
func CheckSocketPath(name string) error {
	lfi, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if err := checkPlantedByOtherUser(name, lfi); err != nil {
		return err
	}
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", name)
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(name)
		if err != nil {
			return err
		}
		return checkPlantedByOtherUser(target, fi)
	}
	return nil
}

func checkPlantedByOtherUser(name string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) == os.Getuid() || st.Uid == 0 {
		return nil
	}
	dir, err := os.Stat(filepath.Dir(name))
	if err != nil {
		return err
	}
	if dir.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("refusing to use %s: owned by uid %d in a world-writable directory", name, st.Uid)
	}
	return nil
}
