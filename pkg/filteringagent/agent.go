package filteringagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrNotSupported = errors.New("agent operation not supported")
	ErrNoSuchKey    = errors.New("agent does not have the specified key")
)

func New(targetAgent agent.Agent, ca ssh.PublicKey, signatureFormat string, keyType string) agent.Agent {
	return &filteringAgent{
		ca:              ca,
		signatureFormat: signatureFormat,
		keyType:         keyType,
		agent:           targetAgent,
		addedKeys:       make(map[string]bool),
	}
}

type filteringAgent struct {
	ca              ssh.PublicKey
	signatureFormat string
	keyType         string

	agent     agent.Agent
	addedKeys map[string]bool
}

func (a *filteringAgent) List() ([]*agent.Key, error) {
	keys, err := a.agent.List()
	if err != nil {
		return nil, err
	}
	var out []*agent.Key
	for _, rawKey := range keys {
		key, err := ssh.ParsePublicKey(rawKey.Marshal())
		if err != nil {
			return nil, err
		}
		if a.addedKeys[fingerprintSHA256(key)] {
			out = append(out, rawKey)
			continue
		}

		cert, _ := key.(*ssh.Certificate)
		if cert == nil {
			continue
		}
		if a.ca != nil && !bytes.Equal(cert.SignatureKey.Marshal(), a.ca.Marshal()) {
			continue
		}
		if a.signatureFormat != "" && cert.Signature.Format != a.signatureFormat {
			continue
		}
		if a.keyType != "" && cert.Key.Type() != a.keyType {
			continue
		}
		out = append(out, rawKey)
	}
	return out, nil
}

func (a *filteringAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	keys, err := a.List()
	if err != nil {
		return nil, err
	}
	var found bool
	for _, rawKey := range keys {
		if bytes.Equal(key.Marshal(), rawKey.Marshal()) {
			found = true
		}
	}
	if !found {
		return nil, ErrNoSuchKey
	}
	return a.agent.Sign(key, data)
}

func (a *filteringAgent) Add(key agent.AddedKey) error {
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}
	if err := a.agent.Add(key); err != nil {
		return nil
	}
	a.addedKeys[fingerprintSHA256(signer.PublicKey())] = true
	if key.Certificate != nil {
		a.addedKeys[fingerprintSHA256(key.Certificate)] = true
	}
	return nil
}

func (a *filteringAgent) Remove(key ssh.PublicKey) error {
	if !a.addedKeys[fingerprintSHA256(key)] {
		return ErrNoSuchKey
	}

	if err := a.agent.Remove(key); err != nil {
		return err
	}
	delete(a.addedKeys, fingerprintSHA256(key))
	return nil
}

func (a *filteringAgent) RemoveAll() error {
	keys, err := a.List()
	if err != nil {
		return err
	}
	for _, rawKey := range keys {
		if !a.addedKeys[fingerprintSHA256(rawKey)] {
			continue
		}
		agentKey, err := ssh.ParsePublicKey(rawKey.Marshal())
		if err != nil {
			return err
		}
		if err := a.agent.Remove(agentKey); err != nil {
			return err
		}
		delete(a.addedKeys, fingerprintSHA256(agentKey))
	}
	return nil
}

func (a *filteringAgent) Lock(_ []byte) error {
	return ErrNotSupported
}

func (a *filteringAgent) Unlock(_ []byte) error {
	return ErrNotSupported
}

func (a *filteringAgent) Signers() ([]ssh.Signer, error) {
	return nil, ErrNotSupported
}

func fingerprintSHA256(key interface{ Marshal() []byte }) string {
	sha256sum := sha256.Sum256(key.Marshal())
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + hash
}
