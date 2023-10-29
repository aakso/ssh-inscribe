package filteringagent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/keysigner"
)

type certsAndKeys struct {
	ca1                             *rsa.PrivateKey
	ca1Cert1Rsa                     *ssh.Certificate
	ca1Cert1KeyRsa                  *rsa.PrivateKey
	ca1Cert2Ed25519                 *ssh.Certificate
	ca1Cert2KeyEd25519              ed25519.PrivateKey
	ca1Cert3RsaLegacySigningAlgo    *ssh.Certificate
	ca1Cert3RsaKeyLegacySigningAlgo *rsa.PrivateKey
	ca2                             ed25519.PrivateKey
	ca2CertRsa                      *ssh.Certificate
	ca2CertRsaKey                   *rsa.PrivateKey
}

func (c *certsAndKeys) addCertsToAgent(t *testing.T, a agent.Agent, skipCa2 bool) {
	var err error
	checkErr := func(err error) {
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	}
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert1KeyRsa, Certificate: c.ca1Cert1Rsa})
	checkErr(err)
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert1KeyRsa})
	checkErr(err)
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert2KeyEd25519, Certificate: c.ca1Cert2Ed25519})
	checkErr(err)
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert2KeyEd25519})
	checkErr(err)
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert3RsaKeyLegacySigningAlgo, Certificate: c.ca1Cert3RsaLegacySigningAlgo})
	checkErr(err)
	err = a.Add(agent.AddedKey{PrivateKey: c.ca1Cert3RsaKeyLegacySigningAlgo})
	checkErr(err)
	if !skipCa2 {
		err = a.Add(agent.AddedKey{PrivateKey: c.ca2CertRsaKey, Certificate: c.ca2CertRsa})
		checkErr(err)
		err = a.Add(agent.AddedKey{PrivateKey: c.ca2CertRsaKey})
		checkErr(err)
	}
}

func testDeps(t *testing.T) *certsAndKeys {
	var (
		r   certsAndKeys
		err error
	)
	checkErr := func(err error) {
		if err != nil {
			assert.FailNow(t, err.Error())
		}
	}
	makeCert := func(ca crypto.PrivateKey, certKey crypto.PrivateKey, signingAlgo string) *ssh.Certificate {
		certKeySigner, err := ssh.NewSignerFromKey(certKey)
		checkErr(err)
		cert := &ssh.Certificate{
			Key:         certKeySigner.PublicKey(),
			CertType:    ssh.UserCert,
			KeyId:       "test",
			ValidAfter:  uint64(time.Now().Unix()),
			ValidBefore: uint64(time.Now().Add(60 * time.Minute).Unix()),
		}
		signer, err := ssh.NewSignerFromKey(ca)
		checkErr(err)
		err = keysigner.SignCertWithAlgorithm(cert, signer, signingAlgo)
		checkErr(err)
		return cert
	}

	r.ca1, err = rsa.GenerateKey(rand.Reader, 2048)
	checkErr(err)
	r.ca1Cert1KeyRsa, err = rsa.GenerateKey(rand.Reader, 2048)
	checkErr(err)
	r.ca1Cert1Rsa = makeCert(r.ca1, r.ca1Cert1KeyRsa, ssh.KeyAlgoRSASHA512)

	_, r.ca1Cert2KeyEd25519, err = ed25519.GenerateKey(rand.Reader)
	checkErr(err)
	r.ca1Cert2Ed25519 = makeCert(r.ca1, r.ca1Cert2KeyEd25519, ssh.KeyAlgoRSASHA512)

	r.ca1Cert3RsaKeyLegacySigningAlgo, err = rsa.GenerateKey(rand.Reader, 2048)
	checkErr(err)
	r.ca1Cert3RsaLegacySigningAlgo = makeCert(r.ca1, r.ca1Cert3RsaKeyLegacySigningAlgo, ssh.KeyAlgoRSA)

	_, r.ca2, err = ed25519.GenerateKey(rand.Reader)
	checkErr(err)
	r.ca2CertRsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
	checkErr(err)
	r.ca2CertRsa = makeCert(r.ca2, r.ca2CertRsaKey, ssh.KeyAlgoED25519)

	return &r
}

func Test_filteringAgent_Add(t *testing.T) {
	ta := agent.NewKeyring()
	deps := testDeps(t)
	deps.addCertsToAgent(t, ta, true)

	taKeys, err := ta.List()
	if !assert.NoError(t, err) {
		return
	}
	lenTaKeys := len(taKeys)

	ca1, err := ssh.NewSignerFromKey(deps.ca1)
	if !assert.NoError(t, err) {
		return
	}
	fa := New(ta, ca1.PublicKey(), "", "")
	if !assert.NoError(t, fa.Add(agent.AddedKey{PrivateKey: deps.ca2CertRsaKey, Certificate: deps.ca2CertRsa})) {
		return
	}
	if !assert.NoError(t, fa.Add(agent.AddedKey{PrivateKey: deps.ca2CertRsaKey})) {
		return
	}

	taKeys, err = ta.List()
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, taKeys, lenTaKeys+2)

	agentKeys, err := fa.List()
	if !assert.NoError(t, err) {
		return
	}
	var addedCertFound bool
	for _, agentKey := range agentKeys {
		key, err := ssh.ParsePublicKey(agentKey.Blob)
		if !assert.NoError(t, err) {
			return
		}
		if cert, ok := key.(*ssh.Certificate); ok {
			if bytes.Equal(cert.Marshal(), deps.ca2CertRsa.Marshal()) {
				addedCertFound = true
			}
		} else {
			addedKey, err := ssh.NewSignerFromKey(deps.ca2CertRsaKey)
			if !assert.NoError(t, err) {
				return
			}
			assert.True(t, bytes.Equal(addedKey.PublicKey().Marshal(), key.Marshal()))
		}
	}
	assert.True(t, addedCertFound)

}

func Test_filteringAgent_List(t *testing.T) {
	ta := agent.NewKeyring()
	deps := testDeps(t)
	deps.addCertsToAgent(t, ta, false)

	t.Run("Ca1_SignAlgo_RSA_SHA2_512", func(t *testing.T) {
		ca1, err := ssh.NewSignerFromKey(deps.ca1)
		if !assert.NoError(t, err) {
			return
		}
		fa := New(ta, ca1.PublicKey(), ssh.KeyAlgoRSASHA512, "")
		agentKeys, err := fa.List()
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, agentKeys, 2)
		for _, agentKey := range agentKeys {
			key, err := ssh.ParsePublicKey(agentKey.Blob)
			if !assert.NoError(t, err) {
				return
			}
			if !assert.IsType(t, &ssh.Certificate{}, key) {
				return
			}
			assert.True(t, bytes.Equal(key.(*ssh.Certificate).SignatureKey.Marshal(), ca1.PublicKey().Marshal()))
			assert.Contains(t, []string{ssh.KeyAlgoRSA, ssh.KeyAlgoED25519}, key.(*ssh.Certificate).Key.Type())
		}
	})
	t.Run("Ca1_SignAlgo_RSA_SHA2_512_KeyType_ED25519", func(t *testing.T) {
		ca1, err := ssh.NewSignerFromKey(deps.ca1)
		if !assert.NoError(t, err) {
			return
		}
		fa := New(ta, ca1.PublicKey(), ssh.KeyAlgoRSASHA512, ssh.KeyAlgoED25519)
		agentKeys, err := fa.List()
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, agentKeys, 1)
		for _, agentKey := range agentKeys {
			key, err := ssh.ParsePublicKey(agentKey.Blob)
			if !assert.NoError(t, err) {
				return
			}
			if !assert.IsType(t, &ssh.Certificate{}, key) {
				return
			}
			assert.True(t, bytes.Equal(key.(*ssh.Certificate).SignatureKey.Marshal(), ca1.PublicKey().Marshal()))
			assert.Equal(t, ssh.KeyAlgoED25519, key.(*ssh.Certificate).Key.Type())
		}
	})
	t.Run("Ca2_SignAlgo_ED25519_KeyType_RSA", func(t *testing.T) {
		ca2, err := ssh.NewSignerFromKey(deps.ca2)
		if !assert.NoError(t, err) {
			return
		}
		fa := New(ta, ca2.PublicKey(), ssh.KeyAlgoED25519, ssh.KeyAlgoRSA)
		agentKeys, err := fa.List()
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, agentKeys, 1)
		for _, agentKey := range agentKeys {
			key, err := ssh.ParsePublicKey(agentKey.Blob)
			if !assert.NoError(t, err) {
				return
			}
			if !assert.IsType(t, &ssh.Certificate{}, key) {
				return
			}
			assert.True(t, bytes.Equal(key.(*ssh.Certificate).SignatureKey.Marshal(), ca2.PublicKey().Marshal()))
			assert.Equal(t, ssh.KeyAlgoRSA, key.(*ssh.Certificate).Key.Type())
		}
	})

}

func Test_filteringAgent_Remove(t *testing.T) {
	ta := agent.NewKeyring()
	deps := testDeps(t)
	deps.addCertsToAgent(t, ta, true)

	taKeys, err := ta.List()
	if !assert.NoError(t, err) {
		return
	}
	lenTaKeys := len(taKeys)

	ca1, err := ssh.NewSignerFromKey(deps.ca1)
	if !assert.NoError(t, err) {
		return
	}
	fa := New(ta, ca1.PublicKey(), "", "")
	if !assert.NoError(t, fa.Add(agent.AddedKey{PrivateKey: deps.ca2CertRsaKey})) {
		return
	}
	signer, err := ssh.NewSignerFromKey(deps.ca2CertRsaKey)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NoError(t, fa.Remove(signer.PublicKey())) {
		return
	}

	taKeys, err = ta.List()
	if !assert.NoError(t, err) {
		return
	}

	assert.Len(t, taKeys, lenTaKeys)
}

func Test_filteringAgent_RemoveAll(t *testing.T) {
	ta := agent.NewKeyring()
	deps := testDeps(t)
	deps.addCertsToAgent(t, ta, true)

	taKeys, err := ta.List()
	if !assert.NoError(t, err) {
		return
	}
	lenTaKeys := len(taKeys)

	ca1, err := ssh.NewSignerFromKey(deps.ca1)
	if !assert.NoError(t, err) {
		return
	}
	fa := New(ta, ca1.PublicKey(), "", "")
	faKeys, err := ta.List()
	if !assert.NoError(t, err) {
		return
	}
	lenFaKeys := len(faKeys)

	if !assert.NoError(t, fa.Add(agent.AddedKey{PrivateKey: deps.ca2CertRsaKey})) {
		return
	}
	if !assert.NoError(t, fa.RemoveAll()) {
		return
	}

	taKeys, err = ta.List()
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, taKeys, lenTaKeys)

	faKeys, err = ta.List()
	if !assert.NoError(t, err) {
		return
	}
	assert.Len(t, faKeys, lenFaKeys)
}

func Test_filteringAgent_Sign(t *testing.T) {
	ta := agent.NewKeyring()
	deps := testDeps(t)
	deps.addCertsToAgent(t, ta, false)

	ca1, err := ssh.NewSignerFromKey(deps.ca1)
	if !assert.NoError(t, err) {
		return
	}

	fa := New(ta, ca1.PublicKey(), "", "")

	data := []byte("fake")
	signature, err := fa.Sign(deps.ca1Cert1Rsa, data)
	if assert.NoError(t, err) {
		signer, err := ssh.NewSignerFromKey(deps.ca1Cert1KeyRsa)
		if assert.NoError(t, err) {
			assert.NoError(t, signer.PublicKey().Verify(data, signature))
		}
	}

	t.Run("FilteredCert", func(t *testing.T) {
		data := []byte("fake2")
		_, err := ta.Sign(deps.ca2CertRsa, data)
		assert.NoError(t, err)

		_, err = fa.Sign(deps.ca2CertRsa, data)
		assert.EqualError(t, ErrNoSuchKey, err.Error())
	})
}
