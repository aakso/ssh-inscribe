//go:build !windows

package filteringagent

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/util"
)

// OpenSSH signs with an RSA key in the agent through the filtering agent.
func Test_filteringAgent_OpenSSHSignsWithRSA(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	ln, err := util.LocalListen(sock)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	// Default sshi setup: RSA user key, CA signature format rsa-sha2-256
	fa := New(agent.NewKeyring(), nil, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, fa.Add(agent.AddedKey{PrivateKey: key}))
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = agent.ServeAgent(fa, conn)
			}()
		}
	}()

	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	pubFile := filepath.Join(dir, "id_rsa.pub")
	require.NoError(t, os.WriteFile(pubFile, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600))
	dataFile := filepath.Join(dir, "data")
	require.NoError(t, os.WriteFile(dataFile, []byte("data"), 0o600))

	cmd := exec.CommandContext(t.Context(), keygen, "-Y", "sign", "-n", "test", "-f", pubFile, dataFile) //nolint:gosec // ssh-keygen from PATH with test files
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.FileExists(t, dataFile+".sig")
}
