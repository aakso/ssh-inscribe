//go:build !windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/util"
)

func TestAdhocAgent(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := util.LocalListen(sock)
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "test"}))
	startAdhocAgent(ln, keyring)

	// Several clients, one after another and concurrently
	for range 3 {
		conn, err := util.DialUnix(sock)
		require.NoError(t, err)
		keys, err := agent.NewClient(conn).List()
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		_ = conn.Close()
	}

	// Closing the listener stops the agent once open connections are done
	open, err := util.DialUnix(sock)
	require.NoError(t, err)
	_, err = agent.NewClient(open).List() // make sure it has been accepted
	require.NoError(t, err)
	require.NoError(t, ln.Close())
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("agent stopped while a connection was still open")
	case <-time.After(100 * time.Millisecond):
	}
	_ = open.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after the listener was closed")
	}

	_, err = util.DialUnix(sock)
	assert.Error(t, err)
}

func TestLocalListenSocketIsPrivate(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := util.LocalListen(sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	require.NoError(t, util.CheckSocketPath(sock))

	fi, err := os.Lstat(sock)
	require.NoError(t, err)
	assert.Zero(t, fi.Mode().Perm()&0o077, "socket must only be accessible by the owner")
}
