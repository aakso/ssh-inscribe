package authfile

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/stretchr/testify/assert"
)

var tmpfiles []string
var testAuth auth.Authenticator

func makeFile(data string, suffix string) string {
	file, err := ioutil.TempFile(os.TempDir(), "test")
	defer file.Close()
	if err != nil {
		panic(err)
	}
	tmpfiles = append(tmpfiles, file.Name())
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
	return name
}

func TestMain(m *testing.M) {
	logging.SetLevel(logrus.DebugLevel)
	r := m.Run()
	for _, file := range tmpfiles {
		os.Remove(file)
	}
	os.Exit(r)
}

func TestAuthFileParse(t *testing.T) {
	assert := assert.New(t)
	data := `
users:
- name: user1
  password: foo
  principals:
  - p1
  - p2
  extensions:
    foo: ""
- name: user2
  password: $2a$11$aaTtm52uHC5dzqf1CEMzqOQ9Fj1sM5QzliEwmqmcON5XnuCnVUWMi # foo
  principals:
  - p1
`
	loc := makeFile(data, "yaml")
	auth, err := New(&Config{
		Path:  loc,
		Realm: "test",
	})
	assert.NoError(err)
	testAuth = auth
}

func TestAuthPlainSuccess(t *testing.T) {
	assert := assert.New(t)
	ctx, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user1", Secret: []byte("foo")})
	assert.True(ok)
	fmt.Println(ctx.GetSubjectName())
}

func TestAuthBcryptSuccess(t *testing.T) {
	assert := assert.New(t)
	ctx, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user2", Secret: []byte("foo")})
	assert.True(ok)
	fmt.Println(ctx.GetSubjectName())
}

func TestAuthPlainFail(t *testing.T) {
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user1", Secret: []byte("notcorrect")})
	assert.False(ok)
}

func TestAuthBcryptFail(t *testing.T) {
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "user2", Secret: []byte("notcorrect")})
	assert.False(ok)
}

func TestAuthUnknownUser(t *testing.T) {
	assert := assert.New(t)
	_, ok := testAuth.Authenticate(nil, &auth.Credentials{UserIdentifier: "nonexistent", Secret: []byte("notcorrect")})
	assert.False(ok)
}
