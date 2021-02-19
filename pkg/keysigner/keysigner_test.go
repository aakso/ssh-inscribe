package keysigner

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	testCaPublic       = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJrN8GEW7E0zsAUQN5xeaDSxo1KEUuIw4yMgLqeBKtyU80UCkJBhXF9K2boukTCUSkZinJOmCQBmDQxaMOT/k52NSMCQzGqzjBeiMxdflR75cgoAFgDL8fzkWfFWP6P/psVC/AeIwiPHHk4Kv4DYuDKgreB+8kMK8nHezoo6q4nxSaRO1zWa4kq17ce7ioMIrbZw0ALIB0rfM9+nahAGFbGrZxcUjtqAM7VGZWrVup9ALpDhnflmkyYTAKBVSGVnvQehqFXuK1xpaQ3avZHl085O2/wi4M8jeDpPpawXyoGr/UzCj+OWBsbIYh04MUqbrLWDWzJsE653VGGebo7jZd test-ca`)
	testCaPublicParsed ssh.PublicKey
	testCaPrivatePem   = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
	testCaPublicInvalid     = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4zuD51v17rZ+ZnNPNjSdfrHHg8rnhYts1wJqvMB/LKj817neJ5ONyulat19XmHUSJYC6X+Jw7imK54VmB4eLfJlpXIJjHX+uk18QxXOsDXvI6kK5aMM1huzc1BQequFD5WiN1KW20HHtzhW1XJayb5PUvp1+B6Bc/NeH/Anx3MjRQx/zMqCRczdLGB/hm/R5GTmGnR16sCb7IRfSg3silDe07a3KQE+PxbR9I8DezwQ5wM2tTZgq3fPjWzVcN+aTj4RjpU5BEEVGsMlZqlpsC9pYP89zi6xxq9zTeRO3aVt0uPvTQIPdS3fe97Y5rPx96RxeSLD4tPauz3CpOxze7 invalid`)
	testCaPrivatePemInvalid = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAuM7g+db9e62fmZzTzY0nX6xx4PK54WLbNcCarzAfyyo/Ne53
ieTjcrpWrdfV5h1EiWAul/icO4piueFZgeHi3yZaVyCYx1/rpNfEMVzrA17yOpCu
WjDNYbs3NQUHqrhQ+VojdSlttBx7c4VtVyWsm+T1L6dfgegXPzXh/wJ8dzI0UMf8
zKgkXM3Sxgf4Zv0eRk5hp0derAm+yEX0oN7IpQ3tO2tykBPj8W0fSPA3s8EOcDNr
U2YKt3z41s1XDfmk4+EY6VOQRBFRrDJWapabAvaWD/Pc4uscavc03kTt2lbdLj70
0CD3Ut33ve2Oaz8fekcXkiw+LT2rs9wqTsc3uwIDAQABAoIBAQCxa4MWt+xQgQXY
znOUQbAMLJyDTeNf2q0CdK7MAxJy1FMs7ov6aTBmoze126DxMyXqENmKclVi398Z
/psUkwxgGQzf2l5yAcdTUQV8Mm04pj08Nkv8MB/sdHRyxSpwHlU2ne+ueiBkqndm
FzE6WePVIkC1CCUrrOoseAlH7VYagwg3JfU9R868+on8m42Lg7f/MSmN9coX6wWq
Yno9B25PP1i05YrHQ3fYWuxdoV+VmgBzHgoWTNxXc51bzTK04qUuBYXuE87+U8Ug
IvWmfva0al/zcolaMV3p0VIecmKSsXrRUXwhxd0+VDjU9vGJp0BwAznp2iQ3j9Cn
2Ecg+crxAoGBAOuhFsg3a5t4e5dD3PfVPIaX8Ww5S//OyNmtpL7HSquQYnus9zhi
7OquPfR/nd8MIFBUCeeW4vMD3GFEJ79olH+fEzSvnL0ptmpXzEz5iLPahHJuI8rk
YCZo0CM64vGZ81SqITy0XjzcisNIoI2v0LX+8BCzapmRiKcH8Tn1VQTZAoGBAMjJ
BjCghv+svVQwhSrZOHu1RoQVRXnyn2VOzuBqBjDNxGwl4SGkWSiRULdJJEQDe+MB
gU+8LLEkEfrFD826msbgdqfPBZKp+nlba8uQkbNOm3gXCNC5DlwtMjB4Bu6327V1
Fq2gQ0q127baGnxrNOLf/AC50bPVyB3Wuv/vpvSzAoGBALRj3ion65TZ11yF0txV
foHYPzbIYruTlsa3nmGD91GDNzJRx+5+JbzA6qONM9K32OFGhVKsfFDpysUYRYnP
Saiuoyh5rXhQP9wIHVtsylBO4Yktcu94iXe+VGI0SdwHLXfKy6lKuL7FZOJ+bpQq
XpGGfEl84gZxmXmupenmPVF5AoGANoV/zMyKW/sIHkheoNgDYnRDBbLQ/uBHMDdK
Ld4ceDwnzkYq7/u0yjNLe7m8w0s+5NGPz5sFd8SXrUS9mdvGE6L4FXE9zimh/jo4
9zn2ln4N8Xovxp25rIYJTugI2eHLI2b8FYGjRDJFy01GS+rAnaq8v2W17+NpR9D7
TmxBJckCgYEAus5MAa+iHtX1o1QIfXtjTPqTog9H6uVKc1kFrTS6PRQbQBiFO/MI
lg08jQ8z4TIRwkCmcmw6C/WnW2UShkGIU75umZadDtSsof06MtBEOgIXmgx7xKTb
mU5fO7aSgagjS0fJXWqa2w8oYFTG1dGDg+H0tHvYyH7dTPtEfhM8FV8=
-----END RSA PRIVATE KEY-----`)
	testUserPublic       = []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC32gyZOLC0RHDntCk+0T5pDNYYytfmP/Jzx+tpqNGEuCWnOV9PwBLdRPT2SNIzCq1GBQWYg63GZ4qWbuvSBvo904Y69q0RWugbcNjpclzkJGT0Bl50l/ppeuJ8wLVFnguCH92E2ja/8tiIPtetKGmFDdSTETIRshGUE6PnuPy2/1BL1ES55XfOGLcvzf/yDi+JeuwQqWi8YMxAIm8ug0yn4GPBPK/MNpnMG3AQmwmviQT6nC6Ky/B9VJk2418v++lAgKRXwyqUeaHd2jAj+5lQ72zc3mZjwFnwTZJWySaGtqxQea9l1wYOhZOEyV4+KOgfLoZ3ps+vmMLGSxmnGmAj user`)
	testUserCertReq      *ssh.Certificate
	testCaPrivate        interface{}
	testCaPrivateInvalid interface{}
	socketPath           string = path.Join(os.TempDir(), "keysignertest")
	certValidBefore      uint64 = uint64(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC).Unix())

	socketPathSmartCard string = path.Join(os.TempDir(), "keysignertestsmartcard")
	smartCardId                = os.Getenv("TEST_SMARTCARD_ID")
	smartCardPin               = os.Getenv("TEST_SMARTCARD_PIN")
	benchSmartCard             = os.Getenv("TEST_SMARTCARD_BENCH")
	smartCardSrv        *KeySignerService
)

func wait(fn func() bool) bool {
	timeout := time.After(15 * time.Second)
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

func addKey(srv *KeySignerService, key interface{}) {
	err := srv.client.Add(agent.AddedKey{
		PrivateKey: key,
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
	cc := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			if bytes.Equal(auth.Marshal(), testCaPublicParsed.Marshal()) {
				return true
			}
			return false
		},
	}
	return cc.CheckCert("testprincipal", cert)
}

func setup() {
	fmt.Println("Setup")
	var err error
	testCaPrivate, err = ssh.ParseRawPrivateKey(testCaPrivatePem)
	if err != nil {
		panic(err)
	}
	testCaPrivateInvalid, err = ssh.ParseRawPrivateKey(testCaPrivatePemInvalid)
	if err != nil {
		panic(err)
	}
	testCaPublicParsed, _, _, _, err = ssh.ParseAuthorizedKey(testCaPublic)
	if err != nil {
		panic(err)
	}
	if benchSmartCard != "" && smartCardId != "" && smartCardPin != "" {
		smartCardSrv = New(socketPathSmartCard, "")
		if !wait(smartCardSrv.AgentPing) {
			panic("agent doesn't respond")
		}
		err = smartCardSrv.AddSmartcard(smartCardId, smartCardPin)
		if err != nil {
			panic(err)
		}
		if !wait(smartCardSrv.Ready) {
			panic("agent should be ready for signing, maybe no key on the smartcard?")
		}
	}
}

func teardown() {
	fmt.Println("Teardown")
	if smartCardSrv != nil {
		smartCardSrv.RemoveSmartcard(smartCardId)
		smartCardSrv.Close()
		smartCardSrv.KillAgent()
	}
}

func TestMain(m *testing.M) {
	setup()
	logging.SetLevel(logrus.DebugLevel)
	r := m.Run()
	teardown()
	os.Exit(r)
}

func TestService(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()
	assert.True(wait(srv.AgentPing), "agent should respond")
}

func TestExistingAgent(t *testing.T) {
	assert := assert.New(t)
	srv1 := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv1.KillAgent()
	wait(srv1.AgentPing)
	srv1.Close()
	// Start new service with agent already listening
	srv2 := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv2.Close()
	assert.True(wait(srv2.AgentPing), "agent should respond")
}

func TestAddSigningKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	assert.NoError(srv.AddSigningKey(testCaPrivatePem, "test-ca"))
	assert.Error(srv.AddSigningKey(testCaPrivatePem, "test-ca"))
}

func TestAddInvalidSigningKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	assert.Error(srv.AddSigningKey(testCaPrivatePemInvalid, "test-ca"))
}

func TestExternallyDiscoverAddedKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	addKey(srv, testCaPrivate)
	assert.True(wait(srv.Ready))
}

func TestExternallyDiscoverInvalidAddedKey(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	addKey(srv, testCaPrivateInvalid)
	assert.False(wait(srv.Ready))
}

func TestSign(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
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
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	key, err := srv.GetPublicKey()
	assert.Error(err)
	assert.True(wait(srv.AgentPing))
	addKey(srv, testCaPrivate)
	assert.True(wait(srv.Ready))
	key, err = srv.GetPublicKey()
	assert.NotNil(key)
}

// This test assumes there is usable key on the smartcard
func TestAddSmartCard(t *testing.T) {
	if smartCardId == "" || smartCardPin == "" {
		t.Skip("No TEST_SMARTCARD_ID or TEST_SMARTCARD_PING set")
	}
	assert := assert.New(t)
	srv := New(socketPath, "")
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	err := srv.AddSmartcard(smartCardId, smartCardPin)
	if assert.NoError(err) {
		assert.True(wait(srv.Ready))
	}
	err = srv.RemoveSmartcard(smartCardId)
	assert.NoError(err)
}

// This test assumes there is usable key on the smartcard
func TestSmartCardSessionRecovery(t *testing.T) {
	if smartCardId == "" || smartCardPin == "" {
		t.Skip("No TEST_SMARTCARD_ID or TEST_SMARTCARD_PING set")
	}
	assert := assert.New(t)
	srv := New(socketPath, "")
	defer srv.KillAgent()
	defer srv.Close()
	assert.True(wait(srv.AgentPing))

	err := srv.AddSmartcard(smartCardId, smartCardPin)
	if assert.NoError(err) {
		assert.True(wait(srv.Ready))
	}

	// Simulate failure
	srv.pkcs11SessionLost = true

	userCert := testCert()
	if assert.Error(srv.SignCertificate(userCert), "signing should fail") {
		// Wait until recovery has kicked in
		if assert.True(wait(srv.Ready)) {
			assert.NoError(srv.SignCertificate(userCert), "signing should now work")
		}
	}
}

func TestSigningTest(t *testing.T) {
	assert := assert.New(t)
	srv := New(socketPath, ssh.FingerprintSHA256(testCaPublicParsed))
	defer srv.KillAgent()
	defer srv.Close()

	assert.True(wait(srv.AgentPing))
	addKey(srv, testCaPrivate)
	assert.True(wait(srv.Ready))
	srv.client.RemoveAll()
	assert.True(wait(func() bool {
		return srv.Ready() == false
	}))
}

// This test assumes there is usable key on the smartcard
func BenchmarkSmartCard(b *testing.B) {
	assert := assert.New(b)
	if smartCardSrv == nil {
		b.Skip("No TEST_SMARTCARD_BENCH and TEST_SMARTCARD_ID and TEST_SMARTCARD_PIN set")
	}
	pubkey, err := smartCardSrv.GetPublicKey()
	if assert.NoError(err, "we should have public key on the smartcard") {
		testCaPublicParsed = pubkey

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				userCert := testCert()
				assert.NoError(smartCardSrv.SignCertificate(userCert), "signing should work")
			}
		})
	}
}
