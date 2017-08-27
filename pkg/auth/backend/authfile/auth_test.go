package authfile

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ScaleFT/sshkeys"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

const (
	testPublic     = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDJrN8GEW7E0zsAUQN5xeaDSxo1KEUuIw4yMgLqeBKtyU80UCkJBhXF9K2boukTCUSkZinJOmCQBmDQxaMOT/k52NSMCQzGqzjBeiMxdflR75cgoAFgDL8fzkWfFWP6P/psVC/AeIwiPHHk4Kv4DYuDKgreB+8kMK8nHezoo6q4nxSaRO1zWa4kq17ce7ioMIrbZw0ALIB0rfM9+nahAGFbGrZxcUjtqAM7VGZWrVup9ALpDhnflmkyYTAKBVSGVnvQehqFXuK1xpaQ3avZHl085O2/wi4M8jeDpPpawXyoGr/UzCj+OWBsbIYh04MUqbrLWDWzJsE653VGGebo7jZd test-ca`
	testPrivatePem = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
)

var (
	tmpfiles    []string
	testPrivate interface{}
	testSigner  ssh.Signer
	testAuth    *AuthFile
)

func parsePrivate(data []byte) {
	key, err := sshkeys.ParseEncryptedRawPrivateKey(data, nil)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	testPrivate = key
	testSigner = signer
}

func makeFile(data string, suffix string) string {
	file, err := ioutil.TempFile(os.TempDir(), "test")
	defer file.Close()
	if err != nil {
		panic(err)
	}
	_, err = file.WriteString(data)
	if err != nil {
		panic(err)
	}
	name := file.Name()
	if suffix != "" {
		newname := path.Join(path.Dir(name), path.Base(name)+"."+suffix)
		err := os.Rename(name, newname)
		if err != nil {
			panic(err)
		}
		name = newname
	}
	tmpfiles = append(tmpfiles, name)
	return name
}

func initBackend(t *testing.T) {
	assert := assert.New(t)
	data := fmt.Sprintf(`
users:
- name: user1
  password: foo
  principals:
  - p1
  - p2
  extensions:
    foo: ""
- name: user2
  password: "$2a$11$aaTtm52uHC5dzqf1CEMzqOQ9Fj1sM5QzliEwmqmcON5XnuCnVUWMi"
  publicKey: "%s"
  principals:
  - p1
`, testPublic)
	loc := makeFile(data, "yaml")
	auth, err := New(&Config{
		Path:           loc,
		Realm:          "test",
		CredentialType: "password",
	})
	if !assert.NoError(err) {
		panic(err)
	}
	testAuth = auth
}

func TestMain(m *testing.M) {
	logging.SetLevel(logrus.DebugLevel)
	r := m.Run()
	for _, file := range tmpfiles {
		os.Remove(file)
	}
	os.Exit(r)
}

func TestAuthPlainSuccess(t *testing.T) {
	initBackend(t)
	assert := assert.New(t)
	ctx, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user1", Secret: []byte("foo")})
	assert.True(ok)
	fmt.Println(ctx.GetSubjectName())
}

func TestAuthBcryptSuccess(t *testing.T) {
	initBackend(t)
	assert := assert.New(t)
	ctx, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user2", Secret: []byte("foo")})
	assert.True(ok)
	fmt.Println(ctx.GetSubjectName())
}

func TestAuthPlainFail(t *testing.T) {
	initBackend(t)
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user1", Secret: []byte("notcorrect")})
	assert.False(ok)
}

func TestAuthBcryptFail(t *testing.T) {
	initBackend(t)
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user2", Secret: []byte("notcorrect")})
	assert.False(ok)
}

func TestAuthUnknownUser(t *testing.T) {
	initBackend(t)
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "nonexistent", Secret: []byte("notcorrect")})
	assert.False(ok)
}

func TestAuthSSHKey(t *testing.T) {
	initBackend(t)
	parsePrivate([]byte(testPrivatePem))

	assert := assert.New(t)
	testAuth.config.CredentialType = "sshkey"
	ctx, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user2"})
	assert.True(ok)
	if !assert.NotNil(ctx) {
		return
	}
	assert.Equal(auth.StatusPending, ctx.Status)
	challenge := ctx.GetMetaString(auth.MetaChallenge)
	if !assert.NotEmpty(challenge) {
		return
	}
	sig, err := testSigner.Sign(rand.Reader, []byte(challenge))
	if !assert.NoError(err) {
		return
	}
	msig, err := json.Marshal(sig)
	if !assert.NoError(err) {
		return
	}
	ctx, ok = testAuth.Authenticate(ctx, &auth.Credentials{UserIdentifier: "user2", Secret: msig})
	assert.True(ok)
	if !assert.NotNil(ctx) {
		return
	}
	assert.Equal(auth.StatusCompleted, ctx.Status)
}
