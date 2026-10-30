package keysigner

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAgent reads one request from the pipe and answers with the given raw
// bytes.
func fakeAgent(t *testing.T, reply []byte) *KeySignerService {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	go func() {
		var size [4]byte
		if _, err := io.ReadFull(server, size[:]); err != nil {
			return
		}
		if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint32(size[:]))); err != nil {
			return
		}
		_, _ = server.Write(reply)
	}()
	return &KeySignerService{conn: client}
}

func frame(payload ...byte) []byte {
	n := len(payload)
	if n < 0 || n > maxAgentResponseBytes {
		panic("frame too large")
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(n)), payload...)
}

func TestCallAgent(t *testing.T) {
	reply, err := fakeAgent(t, frame(agentSuccess)).callAgent([]byte{1, 2, 3})
	require.NoError(t, err)
	assert.IsType(t, &successAgentMsg{}, reply)

	reply, err = fakeAgent(t, frame(agentFailure)).callAgent([]byte{1})
	require.NoError(t, err)
	assert.IsType(t, &failureAgentMsg{}, reply)

	_, err = fakeAgent(t, frame(99)).callAgent([]byte{1})
	assert.Error(t, err, "unknown reply type")

	_, err = fakeAgent(t, frame()).callAgent([]byte{1})
	assert.Error(t, err, "empty reply")
}

func TestCallAgentResponseTooLarge(t *testing.T) {
	// Only the length prefix is sent; the size check must fail before
	// reading the body and must report an error (it used to return nil).
	reply, err := fakeAgent(t, binary.BigEndian.AppendUint32(nil, maxAgentResponseBytes+1)).callAgent([]byte{1})
	assert.Error(t, err)
	assert.Nil(t, reply)
}

func TestCallAgentRequestTooLarge(t *testing.T) {
	ks := &KeySignerService{} // no connection: must fail before writing
	_, err := ks.callAgent(make([]byte, maxAgentResponseBytes+1))
	assert.Error(t, err)
}

func TestReconnectChecksSocketPath(t *testing.T) {
	notASocket := filepath.Join(t.TempDir(), "agent.sock")
	require.NoError(t, os.WriteFile(notASocket, nil, 0o600))
	ks := &KeySignerService{authSocketLoc: notASocket, log: Log}
	assert.False(t, ks.reconnect(), "must refuse a path that is not a socket")
	assert.Nil(t, ks.conn)

	ks = &KeySignerService{authSocketLoc: filepath.Join(t.TempDir(), "missing"), log: Log}
	assert.False(t, ks.reconnect())
}
