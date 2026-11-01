//go:build !windows

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultAgentSocketIsPrivate(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	sock := defaultAgentSocket()
	assert.Equal(t, tmp, filepath.Dir(filepath.Dir(sock)), "test builds have no varDir")
	require.NoError(t, ensureAgentSocketDir(sock))
	fi, err := os.Stat(filepath.Dir(sock))
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, os.FileMode(0o700), fi.Mode().Perm())
	require.NoError(t, ensureAgentSocketDir(sock), "existing directory")

	// Configured sockets elsewhere are left alone
	other := filepath.Join(tmp, "missing", "agent.sock")
	require.NoError(t, ensureAgentSocketDir(other))
	assert.NoDirExists(t, filepath.Dir(other))
}
