package keysigner

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/pkg/util"
)

// Taken from stdlib to allow us to talk to the agent directly
// maxAgentResponseBytes is the maximum agent reply size that is accepted. This
// is a sanity check, not a limit in the spec.
const maxAgentResponseBytes = 16 << 20
const agentFailure = 5

type failureAgentMsg struct{}

const agentSuccess = 6

type successAgentMsg struct{}

// From PROTOCOL.agent 2.2.4
type addSmartcardKeysToAgentReq struct {
	Id          string `sshtype:"20|26"`
	Pin         string
	Constraints []byte `ssh:"rest"`
}

// 2.4.3
type removeSmartcardKeysFromAgentReq struct {
	Id  string `sshtype:"21"`
	Pin string
}

type KeySignerService struct {
	log                 *logrus.Entry
	authSocketLoc       string
	startedAgentProcess *os.Process
	client              agent.Agent
	conn                net.Conn

	chClose chan struct{}
	wg      sync.WaitGroup

	preferredSigningKeyHash string
	selectedSigningKey      *agent.Key

	// Keep state of smartcard keys loaded by us, SHA256 fingerprint is used as a key
	knownSmartCardKeys map[string]*agent.Key

	// PKCS11 stuff
	pkcs11Provider    string
	pkcs11Pin         string
	pkcs11SessionLost bool

	// Signing test
	signTestFailed bool

	sync.Mutex
}

func New(socketPath, preferredKeyHash string) *KeySignerService {
	r := &KeySignerService{
		authSocketLoc:           socketPath,
		log:                     Log.WithField("component", "service"),
		chClose:                 make(chan struct{}),
		preferredSigningKeyHash: preferredKeyHash,
	}
	r.wg.Add(1)
	go r.worker()
	return r
}

func (ks *KeySignerService) isKnownSmartCardKey(key *agent.Key) bool {
	hash := ssh.FingerprintSHA256(key)
	_, ok := ks.knownSmartCardKeys[hash]
	return ok
}

func (ks *KeySignerService) discoverSigningKey() bool {
	if ks.selectedSigningKey != nil {
		return true
	}
	keys, err := ks.client.List()
	if err != nil {
		ks.log.WithError(err).Error("cannot discover keys")
		return false
	}
	for _, key := range keys {
		if ks.preferredSigningKeyHash != "" {
			if ssh.FingerprintSHA256(key) == ks.preferredSigningKeyHash {
				ks.log.WithField("fingerprint", ssh.FingerprintSHA256(key)).Info("configured key found")
				ks.selectedSigningKey = key
				return true
			}
			ks.log.WithField("fingerprint", ssh.FingerprintSHA256(key)).Debug("skipping key, fingerprint doesn't match")
		} else {
			// Take the first key if there is no preference
			ks.log.WithField("fingerprint", ssh.FingerprintSHA256(key)).
				Warning("first key selected, consider setting key fingerprint in configuration")
			ks.selectedSigningKey = key
			return true
		}
	}
	ks.log.Warning("there are no keys on the agent")
	return false
}

func (ks *KeySignerService) Ready() bool {
	ks.Lock()
	defer ks.Unlock()
	if ks.selectedSigningKey == nil {
		return false
	}
	if ks.signTestFailed == true {
		return false
	}
	keys, err := ks.client.List()
	if err != nil {
		return false
	}
	for _, key := range keys {
		if bytes.Compare(key.Blob, ks.selectedSigningKey.Blob) == 0 {
			// Check if we are using pkcs11 and it has failed
			if ks.pkcs11Provider != "" && ks.isKnownSmartCardKey(key) && ks.pkcs11SessionLost == true {
				return false
			}
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

func (ks *KeySignerService) AddSmartcard(id, pin string) error {
	if !ks.AgentPing() {
		return errors.New("cannot add smartcard: agent is not responding")
	}
	ks.Lock()
	defer ks.Unlock()
	return ks.addSmartcard(id, pin)
}
func (ks *KeySignerService) addSmartcard(id, pin string) error {
	// Get current keys from agent
	current, err := ks.client.List()
	if err != nil {
		return err
	}

	// Add current keys to map, use fingerprint as sane key we can't compare
	// the blobs directly
	currentMap := make(map[string]*agent.Key)
	for _, key := range current {
		hash := ssh.FingerprintSHA256(key)
		currentMap[hash] = key
	}

	req := ssh.Marshal(addSmartcardKeysToAgentReq{
		Id:  id,
		Pin: pin,
	})
	res, err := ks.callAgent(req)
	if err != nil {
		return err
	}
	if _, ok := res.(*successAgentMsg); ok {
		ks.pkcs11Provider = id
		ks.pkcs11Pin = pin

		after, err := ks.client.List()
		if err != nil {
			return err
		}

		for _, key := range after {
			hash := ssh.FingerprintSHA256(key)
			_, ok := currentMap[hash]
			if !ok {
				if ks.knownSmartCardKeys == nil {
					ks.knownSmartCardKeys = make(map[string]*agent.Key)
				}
				ks.knownSmartCardKeys[hash] = key
			}
		}

		return nil
	}
	return errors.New("agent: failure")
}

func (ks *KeySignerService) RemoveSmartcard(id string) error {
	if !ks.AgentPing() {
		return errors.New("cannot remove smartcard: agent is not responding")
	}
	ks.Lock()
	defer ks.Unlock()
	return ks.removeSmartcard(id)
}
func (ks *KeySignerService) removeSmartcard(id string) error {
	ks.knownSmartCardKeys = make(map[string]*agent.Key)
	req := ssh.Marshal(removeSmartcardKeysFromAgentReq{
		Id: id,
	})
	res, err := ks.callAgent(req)
	if err != nil {
		return err
	}
	if _, ok := res.(*successAgentMsg); ok {
		ks.pkcs11Provider = ""
		ks.pkcs11Pin = ""
		return nil
	}
	return errors.New("agent: failure")
}

func (ks *KeySignerService) AddSigningKey(encodedKey []byte, passphrase []byte, comment string) error {
	ks.Lock()
	defer ks.Unlock()
	if ks.selectedSigningKey != nil {
		return errors.New("cannot add signing key: there is already signing key added")
	}
	if !ks.agentPing() {
		return errors.New("cannot add signing key: agent is not responding")
	}
	var (
		key interface{}
		err error
	)
	if len(passphrase) > 0 {
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(encodedKey, passphrase)
	} else {
		key, err = ssh.ParseRawPrivateKey(encodedKey)
	}
	if err != nil {
		return errors.Wrap(err, "cannot add signing key")
	}
	// check that fingerprint matches if it is set
	if ks.preferredSigningKeyHash != "" {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return errors.Wrap(err, "cannot add signing key")
		}
		if ssh.FingerprintSHA256(signer.PublicKey()) != ks.preferredSigningKeyHash {
			return errors.New("signing key fingerprint doesn't match the configured value")
		}
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

func (ks *KeySignerService) RemoveAllKeys() error {
	ks.Lock()
	defer ks.Unlock()
	if !ks.agentPing() {
		return errors.New("cannot remove signing key: agent is not responding")
	}
	if ks.pkcs11Provider != "" {
		if err := ks.removeSmartcard(ks.pkcs11Provider); err != nil {
			return errors.Wrap(err, "cannot remove smartcard")
		}
	}
	if err := ks.client.RemoveAll(); err != nil {
		return errors.Wrap(err, "cannot remove signing key")
	}
	ks.selectedSigningKey = nil

	return nil
}

func (ks *KeySignerService) getSigner() (ssh.Signer, error) {
	signers, err := ks.client.Signers()
	if err != nil {
		ks.log.WithError(err).Error("cannot get signers")
		return nil, errors.New("service is not ready for signing")
	}
	if len(signers) == 0 {
		return nil, errors.New("service is not ready for signing")
	}
	for _, signer := range signers {
		if bytes.Compare(signer.PublicKey().Marshal(), ks.selectedSigningKey.Blob) == 0 {
			return signer, nil
		}
	}
	ks.log.Error("selected signing key doesn't match any on the agent")
	return nil, errors.New("service is not ready for signing")
}

func (ks *KeySignerService) SignCertificate(cert *ssh.Certificate, opts crypto.SignerOpts) error {
	if !ks.Ready() {
		return errors.New("service is not ready for signing")
	}
	ks.Lock()
	defer ks.Unlock()

	signer, err := ks.getSigner()
	if err != nil {
		ks.log.Error("cannot get signer")
		return err
	}

	extendedSigner, isExtendedSigner := signer.(util.ExtendedAgentSigner)
	if signer.PublicKey().Type() == "ssh-rsa" && isExtendedSigner {
		signer = &util.ExtendedAgentSignerWrapper{
			Opts:   opts,
			Signer: extendedSigner,
		}
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return err
	} else {
		return nil
	}
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

// This is adapted from ssh/agent/client.go *client.Call
func (ks *KeySignerService) callAgent(req []byte) (reply interface{}, err error) {
	msg := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(msg, uint32(len(req)))
	copy(msg[4:], req)
	if _, err = ks.conn.Write(msg); err != nil {
		return nil, errors.Wrap(err, "agent error")
	}

	var respSizeBuf [4]byte
	if _, err = io.ReadFull(ks.conn, respSizeBuf[:]); err != nil {
		return nil, errors.Wrap(err, "agent error")
	}
	respSize := binary.BigEndian.Uint32(respSizeBuf[:])
	if respSize > maxAgentResponseBytes {
		return nil, errors.Wrap(err, "agent error")
	}

	buf := make([]byte, respSize)
	if _, err = io.ReadFull(ks.conn, buf); err != nil {
		return nil, errors.Wrap(err, "agent error")
	}
	reply, err = unmarshal(buf)
	if err != nil {
		return nil, errors.Wrap(err, "agent error")
	}
	return reply, err
}

func (ks *KeySignerService) startAgent() {
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
	conn, err := net.Dial("unix", ks.authSocketLoc)
	if err != nil {
		ks.log.WithError(err).Error("cannot connect to ssh-agent")
		return false
	}
	ks.log.Info("connected to ssh-agent")
	ks.conn = conn
	ks.client = agent.NewClient(conn)
	return true
}

func (ks *KeySignerService) worker() {
	defer ks.wg.Done()
	for {
		ks.workerAgentCheck()
		ks.workerKeyDiscover()
		ks.workerSignTest()
		ks.workerRecoverPKCS11Session()
		select {
		case <-ks.chClose:
			ks.log.Info("worker exiting")
			return
		case <-time.After(5 * time.Second):
			continue
		}
	}
}

func (ks *KeySignerService) workerSignTest() {
	log := ks.log.WithField("worker", "workerSignTest")
	ks.Lock()
	defer ks.Unlock()

	if ks.selectedSigningKey == nil {
		return
	}
	signer, err := ks.getSigner()
	if err != nil {
		log.WithError(err).Warn("signing key is not available on the agent")
		ks.signTestFailed = true
		return
	}
	data := util.RandBytes(32)
	if _, err := signer.Sign(rand.Reader, data); err != nil {
		// Assume PKCS#11 session is somehow broken on the agent, signal worker to reinsert
		if ks.pkcs11Provider != "" && ks.isKnownSmartCardKey(ks.selectedSigningKey) {
			ks.pkcs11SessionLost = true
		}
		log.WithError(err).Warn("test signing failed, agent is not able to sign")
		ks.signTestFailed = true
	} else {
		ks.signTestFailed = false
	}
}

func (ks *KeySignerService) workerAgentCheck() {
	ks.Lock()
	defer ks.Unlock()
	if !ks.agentPing() && !ks.reconnect() {
		ks.startAgent()
		ks.reconnect()
	}
}

func (ks *KeySignerService) workerKeyDiscover() {
	ks.Lock()
	defer ks.Unlock()
	ks.discoverSigningKey()
}

// This is mainly for problem encountered with Nitrokey HSM
// The PKCS#11 session can become invalid if some other application uses the
// NitroKey HSM thru PKCS#11. Reinserting the card seems to mitigate this,
// thus this worker. This issue is not visible with SoftHSM
func (ks *KeySignerService) workerRecoverPKCS11Session() {
	log := ks.log.WithField("worker", "workerRecoverPKCS11Session")
	ks.Lock()
	defer ks.Unlock()
	if !ks.pkcs11SessionLost {
		return
	}
	log.Warn("attempting to recover from lost PKCS#11 session on the agent")
	// Save pkcs11 settings because successful removal will clear those
	pkcs11Provider := ks.pkcs11Provider
	pkcs11Pin := ks.pkcs11Pin
	if err := ks.removeSmartcard(ks.pkcs11Provider); err != nil {
		log.WithError(err).Error("cannot remove smartcard")
	}
	// Use saved pkcs11 settings to re-add the card since we just cleared it in
	// the removal process
	if err := ks.addSmartcard(pkcs11Provider, pkcs11Pin); err != nil {
		log.WithError(err).Error("cannot add smartcard")
		return
	}
	log.Info("recovered PKCS#11 session")
	ks.pkcs11SessionLost = false
}

func (ks *KeySignerService) Close() {
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

// success/fail handler
func unmarshal(packet []byte) (interface{}, error) {
	if len(packet) < 1 {
		return nil, errors.New("agent: empty packet")
	}
	var msg interface{}
	switch packet[0] {
	case agentFailure:
		return new(failureAgentMsg), nil
	case agentSuccess:
		return new(successAgentMsg), nil
	default:
		return nil, errors.Errorf("agent: unknown type tag %d", packet[0])
	}
	return msg, nil
}
