package keysigner

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	testCaPublic     = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJrN8GEW7E0zsAUQN5xeaDSxo1KEUuIw4yMgLqeBKtyU80UCkJBhXF9K2boukTCUSkZinJOmCQBmDQxaMOT/k52NSMCQzGqzjBeiMxdflR75cgoAFgDL8fzkWfFWP6P/psVC/AeIwiPHHk4Kv4DYuDKgreB+8kMK8nHezoo6q4nxSaRO1zWa4kq17ce7ioMIrbZw0ALIB0rfM9+nahAGFbGrZxcUjtqAM7VGZWrVup9ALpDhnflmkyYTAKBVSGVnvQehqFXuK1xpaQ3avZHl085O2/wi4M8jeDpPpawXyoGr/UzCj+OWBsbIYh04MUqbrLWDWzJsE653VGGebo7jZd test-ca`)
	testCaPrivatePem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAyazfBhFuxNM7AFEDecXmg0saNShFLiMOMjIC6ngSrclPNFAp
CQYVxfStm6LpEwlEpGYpyTpgkAZg0MWjDk/5OdjUjAkMxqs4wXojMXX5Ue+XIKAB
YAy/H85FnxVj+j/6bFQvwHiMIjxx5OCr+A2LgyoK3gfvJDCvJx3s6KOquJ8UmkTt
c1muJKte3Hu4qDCK22cNACyAdK3zPfp2oQBhWxq2cXFI7agDO1RmVq1bqfQC6Q4Z
35ZpMmEwCgVUhlZ70HoahV7itcaWkN2r2R5dPOTtv8IuDPI3g6T6WsF8qBq/1Mwo
/jlgbGyGIdODFKm6y1g1sybBOud1Rhnm6O42XQIDAQABAoIBAG3BCLaysgentQpd
DHku/F4jdyXKvqt3JHiowvF7Wx782X/syAhDKYJLwFdc918GwjZ96uu6O2bmMbYs
eKqHV2jl2fZDzpIoCIEyyQhX3dF7hFGbAmSVS0Yx6a3D5F8ChnSB9GLYt9rB7nHS
24PpSy2cqcFfrAOUAx5UqOOKfpRt91MieRix9PIcjyvrWgVOn8b3gpPRIg7sFK04
RpHv97Qq/8uYYk9P/+KGPgmgyun53RkC3AIlm8bcgMi/D2DZrAMPlU3lKQ3s1UDr
nJm30FW6R3d9d7/L0jZ0lqnBGzQuKxjqY66f25eAw15TtihSWx382TopCXWmakl0
I4rzCAECgYEA6Mp0PxSSbXegPCq6PzpFXPUm9v49LLVB/muLKAdSLinlTRe2lPqF
zLzDuvHXHyETNsEzbgUAtRaN9MgDJ6s254zDjoKN+aFi/5ZDa05WGINBri636qkH
+eCtbaedt+Iz/HBebDNdMmFJbktwwwoGIf06Sg5+NBRImPwrt7giQ10CgYEA3chA
VfnAc2SjbD9/T4kaakf8sMra8X+5y1NW6zAFU1VAAY5/neM9b71w3kU4ZRVMEVes
H64vriIrD3cCgSbMKwUN+6vN+aNTnjrsRJwI1rVl/+M7gfwzRERNOqCfdlrFgcfB
5iDz6GVJWBHwRtMCFpWzS0zm4qHkLue1KFInjwECgYEAmdJVV+1XCGB4j+lH4km1
1cPkOGcssyMedWhIrm2P/xMOAo/9xJl52hyNVTVCib5IPPES88r4ebBqoumbNBYt
lHluKvfXqrDagrqe2AQOXeo1d0xFmRiSPaoZzxBn5j7hTRhPPD4Agi7I38mXvDke
bk0uvAqxl+YjRnuyw5Y3hb0CgYBu6p+CYA2nqEUy9e6t0Futm6L8p/cnoEFDNsLZ
jIKdUp1YKfQY+nTXVV8FSokRxLzuT3J9xZeC9wOiEFroTIb/XN/JZfr1RoGjOMTA
62hgOQhyGSrBr2fUVHRrRbl6b5sndMe8V+6j40PzD8WjJhR9RxEML8Goxl5gNvGa
4Lt4AQKBgHEqMIRDxr9RYbXSlRZqtJRvlN173YbBAdLVg/VUz8jxqXBcQl2AA9Fm
D5sRPJP9cTEWfmrxeZAETGhWxQkQQU956NJdXnLVOCopi2J1rD/Y2waUvGoihSuX
BOKQEAfMgR02w/4NuPb3mX27mk74/MKvR4ixv2zK6ExBL4u4ICdS
-----END RSA PRIVATE KEY-----`)
	testUserPublic  = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC32gyZOLC0RHDntCk+0T5pDNYYytfmP/Jzx+tpqNGEuCWnOV9PwBLdRPT2SNIzCq1GBQWYg63GZ4qWbuvSBvo904Y69q0RWugbcNjpclzkJGT0Bl50l/ppeuJ8wLVFnguCH92E2ja/8tiIPtetKGmFDdSTETIRshGUE6PnuPy2/1BL1ES55XfOGLcvzf/yDi+JeuwQqWi8YMxAIm8ug0yn4GPBPK/MNpnMG3AQmwmviQT6nC6Ky/B9VJk2418v++lAgKRXwyqUeaHd2jAj+5lQ72zc3mZjwFnwTZJWySaGtqxQea9l1wYOhZOEyV4+KOgfLoZ3ps+vmMLGSxmnGmAj user`)
	testUserCertReq *ssh.Certificate
	testCaPrivate   interface{}
	socketPath      string = path.Join(os.TempDir(), "keysignertest")
	certValidBefore uint64 = uint64(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	smartCardId  = os.Getenv("TEST_SMARTCARD_ID")
	smartCardPin = os.Getenv("TEST_SMARTCARD_PIN")
)

func wait(fn func() bool) bool {
	timeout := time.After(6 * time.Second)
	for {
		select {
		case <-timeout:
			return false
		default:
		}
		if fn() {
			return true
		}
	}
}

func addKey(srv *KeySignerService) {
	err := srv.client.Add(agent.AddedKey{
		PrivateKey: testCaPrivate,
		Comment:    "test ca",
	})
	if err != nil {
		panic(err)
	}
}

func testCert() *ssh.Certificate {
	userKey, _, _, _, err := ssh.ParseAuthorizedKey(testUserPublic)
	if err != nil {
		panic(err)
	}
	return &ssh.Certificate{
		Key:             userKey,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"testprincipal"},
		ValidBefore:     certValidBefore,
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}
}

func checkCert(cert *ssh.Certificate) error {
	caPublic, _, _, _, err := ssh.ParseAuthorizedKey(testCaPublic)
	if err != nil {
		panic(err)
	}
	cc := &ssh.CertChecker{
		IsAuthority: func(auth ssh.PublicKey) bool {
			if bytes.Equal(auth.Marshal(), caPublic.Marshal()) {
				return true
			}
			return false
		},
	}
	return cc.CheckCert("testprincipal", cert)
}

func setup() {
	var err error
	testCaPrivate, err = ssh.ParseRawPrivateKey(testCaPrivatePem)
	if err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	setup()
	logging.SetLevel(logrus.DebugLevel)
	os.Exit(m.Run())
}

func TestService(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()
	assert.True(wait(srv.AgentPing), "agent should respond")
}

func TestExistingAgent(t *testing.T) {
	assert := assert.New(t)
	srv1 := New(socketPath)
	defer srv1.KillAgent()
	wait(srv1.AgentPing)
	srv1.Close()
	// Start new service with agent already listening
	srv2 := New(socketPath)
	defer srv2.Close()
	assert.True(wait(srv2.AgentPing), "agent should respond")
}

func TestAddSigningKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	assert.NoError(srv.AddSigningKey(testCaPrivatePem, "test-ca"))
	assert.Error(srv.AddSigningKey(testCaPrivatePem, "test-ca"))
}

func TestDiscoverAddedKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	addKey(srv)
	assert.True(wait(srv.Ready))
}

func TestSign(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	if assert.NoError(srv.AddSigningKey(testCaPrivatePem, "test-ca")) {
		if assert.True(srv.Ready(), "service should be ready") {
			userCert := testCert()
			assert.NoError(srv.SignCertificate(userCert), "signing should work")
			assert.NoError(checkCert(userCert))
			fmt.Println("certificate:", string(ssh.MarshalAuthorizedKey(userCert)))
		}
	}
}

func TestGetPublicKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()

	key, err := srv.GetPublicKey()
	assert.Error(err)
	assert.True(wait(srv.AgentPing))
	addKey(srv)
	assert.True(wait(srv.Ready))
	key, err = srv.GetPublicKey()
	assert.NotNil(key)
}

func TestSmartCard(t *testing.T) {
	if smartCardId == "" || smartCardPin == "" {
		t.Skip("No TEST_SMARTCARD_ID or TEST_SMARTCARD_PING set")
	}
	assert := assert.New(t)
	srv := New(socketPath)
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	err := srv.AddSmartcard(smartCardId, smartCardPin)
	if assert.NoError(err) {
		assert.True(wait(srv.Ready))
	}
	err = srv.RemoveSmartcard(smartCardId)
	assert.NoError(err)
	assert.False(wait(srv.Ready))
}
