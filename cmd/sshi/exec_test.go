//go:build !windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/util"
)

func TestAdhocAgent(t *testing.T) {
	hook := logtest.NewLocal(Log.Logger)
	t.Cleanup(hook.Reset)

	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := util.LocalListen(sock)
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: key, Comment: "test"}))
	adhoc := startAdhocAgent(ln, keyring)

	list := func(conn net.Conn) error {
		_, err := agent.NewClient(conn).List()
		return err
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			conn, err := util.DialUnix(sock)
			if assert.NoError(t, err) {
				assert.NoError(t, list(conn))
				_ = conn.Close()
			}
		})
	}
	wg.Wait()

	// A connection kept open, e.g. by a ControlPersist ssh master with agent
	// forwarding, must not keep sshi from exiting.
	held, err := util.DialUnix(sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = held.Close() })
	require.NoError(t, list(held))

	done := make(chan struct{})
	go func() {
		adhoc.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while a connection was open")
	}
	assert.Error(t, list(held), "open connections are closed")
	_, err = util.DialUnix(sock)
	assert.Error(t, err, "listener is closed")

	for _, e := range hook.AllEntries() {
		assert.NotEqual(t, logrus.ErrorLevel, e.Level, "shutting down must not log errors: %s %v", e.Message, e.Data)
	}
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
