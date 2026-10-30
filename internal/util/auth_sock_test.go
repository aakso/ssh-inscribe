//go:build !windows

package util

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestCheckPlantedByOtherUser(t *testing.T) {
	shared := t.TempDir()
	// The scenario under test is a world-writable directory such as /tmp
	assert.NoError(t, os.Chmod(shared, 0o1777)) //nolint:gosec // intentionally world-writable, see above
	private := t.TempDir()

	fi, err := os.Stat(private)
	if !assert.NoError(t, err) {
		return
	}
	self := fi.Sys().(*syscall.Stat_t).Uid

	other := fakeFileInfo{uid: self + 4242}
	assert.Error(t, checkPlantedByOtherUser(filepath.Join(shared, "s"), other))
	assert.NoError(t, checkPlantedByOtherUser(filepath.Join(private, "s"), other))

	assert.NoError(t, checkPlantedByOtherUser(filepath.Join(shared, "s"), fakeFileInfo{uid: 0}))
	assert.NoError(t, checkPlantedByOtherUser(filepath.Join(shared, "s"), fakeFileInfo{uid: self}))
}
