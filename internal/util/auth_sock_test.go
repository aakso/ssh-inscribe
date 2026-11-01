//go:build !windows

package util

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckSocketPath(t *testing.T) {
	dir := t.TempDir()

	sock := filepath.Join(dir, "agent.sock")
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = ln.Close() }()
	assert.NoError(t, CheckSocketPath(sock))

	link := filepath.Join(dir, "link.sock")
	assert.NoError(t, os.Symlink(sock, link))
	assert.NoError(t, CheckSocketPath(link))

	regular := filepath.Join(dir, "file")
	assert.NoError(t, os.WriteFile(regular, nil, 0o600))
	assert.Error(t, CheckSocketPath(regular))

	assert.True(t, os.IsNotExist(CheckSocketPath(filepath.Join(dir, "missing"))))
}

type fakeFileInfo struct {
	os.FileInfo
	uid uint32
}

func (f fakeFileInfo) Sys() any { return &syscall.Stat_t{Uid: f.uid} }

func selfUID(t *testing.T) uint32 {
	t.Helper()
	fi, err := os.Stat(t.TempDir())
	require.NoError(t, err)
	return fi.Sys().(*syscall.Stat_t).Uid
}

// sharedDir returns a world-writable directory such as /tmp.
func sharedDir(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, mode))
	return dir
}

func listenUnix(t *testing.T, name string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", name)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
}

func TestCheckEntry(t *testing.T) {
	shared := sharedDir(t, os.ModeSticky|0o777)
	sharedFi, err := os.Stat(shared)
	require.NoError(t, err)
	privateFi, err := os.Stat(t.TempDir())
	require.NoError(t, err)
	self := selfUID(t)

	other := fakeFileInfo{uid: self + 4242}
	assert.Error(t, checkEntry(filepath.Join(shared, "s"), other, sharedFi))
	assert.NoError(t, checkEntry("s", other, privateFi), "dedicated agent user")
	assert.NoError(t, checkEntry("s", fakeFileInfo{uid: 0}, sharedFi))
	assert.NoError(t, checkEntry("s", fakeFileInfo{uid: self}, sharedFi))

	nonSticky, err := os.Stat(sharedDir(t, 0o777))
	require.NoError(t, err)
	assert.Error(t, checkEntry("s", fakeFileInfo{uid: self}, nonSticky), "anyone can replace the entry")
}

func TestCheckSocketPathSymlinkChains(t *testing.T) {
	private := t.TempDir()
	sock := filepath.Join(private, "agent.sock")
	listenUnix(t, sock)

	// Own links through a sticky world-writable directory are fine
	shared := sharedDir(t, os.ModeSticky|0o777)
	hop := filepath.Join(shared, "hop")
	require.NoError(t, os.Symlink(sock, hop))
	link := filepath.Join(private, "link")
	require.NoError(t, os.Symlink(hop, link))
	assert.NoError(t, CheckSocketPath(link))

	// Relative links and .. are resolved like the kernel does
	require.NoError(t, os.Mkdir(filepath.Join(private, "sub"), 0o700))
	rel := filepath.Join(private, "sub", "rel")
	require.NoError(t, os.Symlink("../agent.sock", rel))
	assert.NoError(t, CheckSocketPath(rel))

	// A hop through a world-writable directory without the sticky bit is
	// refused, even though the first link and the socket are safe.
	open := sharedDir(t, 0o777)
	openHop := filepath.Join(open, "hop")
	require.NoError(t, os.Symlink(sock, openHop))
	link2 := filepath.Join(private, "link2")
	require.NoError(t, os.Symlink(openHop, link2))
	assert.ErrorContains(t, CheckSocketPath(link2), "without the sticky bit")

	// A socket in such a directory is refused too
	openSock := filepath.Join(open, "agent.sock")
	listenUnix(t, openSock)
	assert.Error(t, CheckSocketPath(openSock))

	loop := filepath.Join(private, "loop")
	require.NoError(t, os.Symlink(loop, loop))
	assert.ErrorContains(t, CheckSocketPath(loop), "too many levels")
}

// Entries owned by another user cannot be created in tests, so fake the
// owner of selected paths.
func TestResolveTrustedOtherOwner(t *testing.T) {
	shared := sharedDir(t, os.ModeSticky|0o777)
	plantedDir := filepath.Join(shared, "ssh-inscribe")
	require.NoError(t, os.Mkdir(plantedDir, 0o700))
	sock := filepath.Join(plantedDir, "agent.sock")
	listenUnix(t, sock)
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(sock, link))

	other := selfUID(t) + 4242
	lstatOwnedBy := func(owned string) func(string) (os.FileInfo, error) {
		return func(name string) (os.FileInfo, error) {
			fi, err := os.Lstat(name)
			if err != nil || name != owned {
				return fi, err
			}
			return fakeFileInfo{FileInfo: fi, uid: other}, nil
		}
	}

	_, err := resolveTrusted(sock, os.Lstat)
	assert.NoError(t, err)
	// The other user's directory in a world-writable directory: the user
	// owns everything below it, the socket included.
	_, err = resolveTrusted(sock, lstatOwnedBy(plantedDir))
	assert.ErrorContains(t, err, "owned by uid")
	_, err = resolveTrusted(link, lstatOwnedBy(plantedDir))
	assert.ErrorContains(t, err, "owned by uid", "reached through a symlink")
	// A socket owned by another user in our own directory is accepted
	_, err = resolveTrusted(sock, lstatOwnedBy(sock))
	assert.NoError(t, err)
}
