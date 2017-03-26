package keysigner

import (
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type KeySignerService struct {
	authSocketLoc       string
	startedAgentProcess *os.Process
	client              agent.Agent
	conn                net.Conn
	chClose             chan struct{}
	wg                  sync.WaitGroup
	log                 *logrus.Entry
	selectedSigningKey  *agent.Key
	sync.Mutex
}

func New(socketPath string) *KeySignerService {
	r := &KeySignerService{
		authSocketLoc: socketPath,
		log:           Log.WithField("component", "service"),
		chClose:       make(chan struct{}),
	}
	r.wg.Add(1)
	go r.worker()
	return r
}

func (ks *KeySignerService) discoverSigningKey() bool {
	if ks.selectedSigningKey != nil {
		return true
	}
	keys, err := ks.client.List()
	if err != nil {
		return false
	}
	if len(keys) == 1 {
		ks.log.WithField("pubkey", string(ssh.MarshalAuthorizedKey(keys[0]))).Info("key found")
		ks.selectedSigningKey = keys[0]
	} else if len(keys) > 1 {
		ks.log.WithField("keys", len(keys)).Error("there are more than one key on the agent")
		return false
	} else {
		ks.log.Warning("there are no keys on the agent")
		return false
	}
	return true
}

func (ks *KeySignerService) Ready() bool {
	ks.Lock()
	defer ks.Unlock()
	if ks.selectedSigningKey == nil {
		return false
	}
	keys, err := ks.client.List()
	if err != nil {
		return false
	}
	for _, key := range keys {
		if bytes.Compare(key.Blob, ks.selectedSigningKey.Blob) == 0 {
			return true
		}
	}
	return false
}

func (ks *KeySignerService) AgentPing() bool {
	ks.Lock()
	defer ks.Unlock()
	return ks.agentPing()
}

func (ks *KeySignerService) agentPing() bool {
	if ks.client == nil {
		return false
	}
	if _, err := ks.client.List(); err != nil {
		return false
	}
	return true
}

func (ks *KeySignerService) GetPublicKey() (ssh.PublicKey, error) {
	ks.Lock()
	defer ks.Unlock()
	if ks.selectedSigningKey == nil {
		return nil, errors.New("no signing key available")
	}
	return ks.selectedSigningKey, nil
}

func (ks *KeySignerService) AddSigningKey(pemKey []byte, comment string) error {
	ks.Lock()
	defer ks.Unlock()
	if ks.selectedSigningKey != nil {
		return errors.New("cannot add signing key: there is already signing key added")
	}
	if !ks.agentPing() {
		return errors.New("cannot add signing key: agent is not responding")
	}
	key, err := ssh.ParseRawPrivateKey(pemKey)
	if err != nil {
		return errors.Wrap(err, "cannot add signing key")
	}
	err = ks.client.Add(agent.AddedKey{
		PrivateKey: key,
		Comment:    comment,
	})
	if err != nil {
		return errors.Wrap(err, "cannot add signing key")
	}
	if !ks.discoverSigningKey() {
		return errors.New("cannot add signing key: agent is not accepting the key")
	}
	return nil
}

func (ks *KeySignerService) SignCertificate(cert *ssh.Certificate) error {
	if !ks.Ready() {
		return errors.New("service is not ready for signing")
	}
	signers, err := ks.client.Signers()
	if err != nil {
		ks.log.WithError(err).Error("cannot get signers")
		return errors.New("service is not ready for signing")
	}
	if len(signers) == 0 {
		ks.log.Error("there are no signers")
		return errors.New("service is not ready for signing")
	}
	for _, signer := range signers {
		if bytes.Compare(signer.PublicKey().Marshal(), ks.selectedSigningKey.Blob) != 0 {
			continue
		}
		return cert.SignCert(rand.Reader, signer)
	}
	ks.log.Error("selected signing key doesn't match any on the agent")
	return errors.New("service is not ready for signing")
}

// Kill agent if it was started by us
func (ks *KeySignerService) KillAgent() bool {
	ks.Lock()
	defer ks.Unlock()
	if ks.startedAgentProcess == nil {
		return false
	}
	if err := ks.startedAgentProcess.Kill(); err != nil {
		ks.log.WithError(err).Error("cannot kill agent")
		return false
	}
	// Ensure socket file is removed, for some reason the cleanup_exit is not called
	// Need to look into that
	os.Remove(ks.authSocketLoc)
	ks.log.WithField("agentpid", ks.startedAgentProcess.Pid).Info("killed ssh-agent")

	ks.startedAgentProcess = nil
	return true
}

func (ks *KeySignerService) startAgent() {
	ks.Lock()
	defer ks.Unlock()
	ks.log.WithField("socket", ks.authSocketLoc).Info("starting ssh-agent")
	if _, err := os.Stat(ks.authSocketLoc); err == nil {
		ks.log.Warning("cannot start ssh-agent. Socket file exists")
		return
	}

	bin, err := exec.LookPath("ssh-agent")
	if err != nil {
		ks.log.Error("ssh-agent not found")
		return
	}

	cmd := exec.Command(bin, "-a", ks.authSocketLoc)
	out, err := cmd.Output()
	if err != nil {
		ks.log.WithError(err).Error("cannot start ssh-agent")
		return
	}
	parts := strings.Split(string(out), "SSH_AGENT_PID=")
	if len(parts) >= 2 {
		parts = strings.Split(parts[1], ";")
		if pid, err := strconv.Atoi(parts[0]); err == nil {
			if proc, err := os.FindProcess(pid); err == nil {
				ks.log.WithField("agentpid", pid).Info("started ssh-agent")
				ks.startedAgentProcess = proc
			}
		}
	}
}

func (ks *KeySignerService) reconnect() bool {
	ks.Lock()
	defer ks.Unlock()
	conn, err := net.Dial("unix", ks.authSocketLoc)
	if err != nil {
		ks.log.WithError(err).Error("cannot connect to ssh-agent")
		return false
	}
	ks.log.Info("connected to ssh-agent")
	ks.client = agent.NewClient(conn)
	return true
}

func (ks *KeySignerService) worker() {
	defer ks.wg.Done()
	for {
		if !ks.AgentPing() && !ks.reconnect() {
			ks.startAgent()
			ks.reconnect()
		}
		ks.Lock()
		ks.discoverSigningKey()
		ks.Unlock()
		select {
		case <-ks.chClose:
			ks.log.Info("worker exiting")
			return
		case <-time.After(5 * time.Second):
			continue
		}
	}
}

func (ks *KeySignerService) Close() {
	ks.Lock()
	defer ks.Unlock()
	select {
	case _, ok := <-ks.chClose:
		if !ok {
			return
		}
	default:
	}
	close(ks.chClose)
	ks.wg.Wait()
}
