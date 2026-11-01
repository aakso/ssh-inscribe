//go:build !windows

package util

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
// sticky bit set, and both it and its entries (such as /tmp and the files in
// it) must be owned by the current user or root. This covers the socket, the
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
	// Not filepath.Abs: it cleans the path, which drops ".." before the
	// symlinks in front of it are resolved.
	cur := "/"
	if !filepath.IsAbs(name) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		cur = wd
	}
	rest := splitPath(name)
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
// replace: anything in a world-writable directory without the sticky bit, and
// in a sticky world-writable directory an entry, or a directory, owned by
// someone other than the current user or root.
func checkEntry(name string, fi, parent os.FileInfo) error {
	if parent.Mode().Perm()&0o002 == 0 {
		return nil
	}
	dir := filepath.Dir(name)
	if parent.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("refusing to use %s: %s is world-writable without the sticky bit", name, dir)
	}
	// The owner of a sticky directory can still remove any entry in it
	if uid, err := untrustedOwner(parent); err != nil || uid != "" {
		return fmt.Errorf("refusing to use %s: world-writable directory %s owned by %s", name, dir, ownerDesc(uid, err))
	}
	if uid, err := untrustedOwner(fi); err != nil || uid != "" {
		return fmt.Errorf("refusing to use %s: owned by %s in a world-writable directory", name, ownerDesc(uid, err))
	}
	return nil
}

// untrustedOwner returns the owner of fi, or "" for the current user and
// root.
func untrustedOwner(fi os.FileInfo) (string, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("unknown owner")
	}
	if int(st.Uid) == os.Getuid() || st.Uid == 0 {
		return "", nil
	}
	return strconv.FormatUint(uint64(st.Uid), 10), nil
}

func ownerDesc(uid string, err error) string {
	if err != nil {
		return err.Error()
	}
	return "uid " + uid
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
