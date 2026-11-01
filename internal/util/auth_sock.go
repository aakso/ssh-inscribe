//go:build !windows

package util

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func DialAuthSock(name string) (net.Conn, error) {
	if name == "" {
		name = os.Getenv("SSH_AUTH_SOCK")
	}
	conn, err := DialUnix(name)
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
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", name)
	if err != nil {
		return nil, fmt.Errorf("could not create a unix listener socket: %w", err)
	}
	return ln, nil
}

// CheckSocketPath verifies that name is a unix socket that another local
// user could not have planted or swapped. Every component of the path is
// checked, following symlinks: a world-writable directory must have the
// sticky bit set, and entries in a world-writable directory (such as /tmp)
// must be owned by the current user or root. This covers the socket, the
// directories leading to it and the symlinks on the way. Entries owned by
// another user elsewhere are accepted, e.g. an agent run by a dedicated user.
func CheckSocketPath(name string) error {
	resolved, err := resolveTrusted(name, os.Lstat)
	if err != nil {
		return err
	}
	fi, err := os.Stat(resolved)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", name)
	}
	return nil
}

// Same limit as Linux (MAXSYMLINKS).
const maxSymlinks = 40

// resolveTrusted resolves name like the kernel does, one component at a
// time, and checks each entry with checkEntry. Errors from lstat are
// returned unwrapped so that os.IsNotExist works.
func resolveTrusted(name string, lstat func(string) (os.FileInfo, error)) (string, error) {
	abs, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	cur := "/"
	rest := splitPath(abs)
	links := 0
	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		parent, err := lstat(cur)
		if err != nil {
			return "", err
		}
		next := filepath.Join(cur, comp)
		fi, err := lstat(next)
		if err != nil {
			return "", err
		}
		if err := checkEntry(next, fi, parent); err != nil {
			return "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		if links++; links > maxSymlinks {
			return "", fmt.Errorf("%s: too many levels of symbolic links", name)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		rest = append(splitPath(target), rest...)
	}
	return cur, nil
}

func splitPath(p string) []string {
	return strings.Split(p, string(filepath.Separator))
}

// checkEntry refuses an entry that another user could have created or can
// replace: anything in a world-writable directory without the sticky bit, or
// an entry owned by someone other than the current user or root in a
// world-writable directory.
func checkEntry(name string, fi, parent os.FileInfo) error {
	if parent.Mode().Perm()&0o002 == 0 {
		return nil
	}
	if parent.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("refusing to use %s: %s is world-writable without the sticky bit", name, filepath.Dir(name))
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("refusing to use %s: cannot determine the owner", name)
	}
	if int(st.Uid) == os.Getuid() || st.Uid == 0 {
		return nil
	}
	return fmt.Errorf("refusing to use %s: owned by uid %d in a world-writable directory", name, st.Uid)
}

// EnsurePrivateDir creates dir accessible only by the current user, or checks
// that an existing dir is such a directory (not a symlink).
func EnsurePrivateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return fmt.Errorf("cannot create %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("refusing to use %s: not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("refusing to use %s: not owned by the current user", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("refusing to use %s: accessible by other users (mode %04o)", dir, fi.Mode().Perm())
	}
	return nil
}
