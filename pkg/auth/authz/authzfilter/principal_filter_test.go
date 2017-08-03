package authzfilter

import (
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/aakso/ssh-inscribe/pkg/logging"
)

func authContext() *auth.AuthContext {
	first := &auth.AuthContext{
		Status:      auth.StatusCompleted,
		SubjectName: "test",
		Principals: []string{
			"first.test1",
			"first.test2",
		},
	}
	second := &auth.AuthContext{
		Status: auth.StatusCompleted,
		Parent: first,
		Principals: []string{
			"second.test1",
			"second.test2",
		},
	}
	return second
}

func TestMain(m *testing.M) {
	logging.SetLevel(logrus.DebugLevel)
	r := m.Run()
	os.Exit(r)
}

func TestFilterInclude(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		FilterIncludePrincipalsGlob: "{first*,second.test1}",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.True(ok, "authorizer should have succeeded")
	assert.NotNil(ctx, "should have received new auth context")
	assert.Contains(ctx.GetPrincipals(), "first.test1")
	assert.Contains(ctx.GetPrincipals(), "first.test2")
	assert.NotContains(ctx.GetPrincipals(), "second.test2")
}

func TestFilterExclude(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		FilterExcludePrincipalsGlob: "{first*,second.test1}",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.True(ok, "authorizer should have succeeded")
	assert.NotNil(ctx, "should have received new auth context")
	assert.Contains(ctx.GetPrincipals(), "second.test2")
}

func TestMustInclude(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		MustIncludePrincipalGlob: "{first*,second.test1}",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.True(ok, "authorizer should have succeeded")
	assert.NotNil(ctx, "should have received new auth context")
	assert.Len(ctx.GetPrincipals(), 4, "should not have removed anything")
}

func TestMustIncludeFail(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		MustIncludePrincipalGlob: "second.testnonexistent",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.False(ok, "authorizer should have failed")
	assert.Nil(ctx, "should not have received new auth context")
}

func TestMustNotInclude(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		MustNotIncludePrincipalGlob: "{third*,fourth.test1}",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.True(ok, "authorizer should have succeeded")
	assert.NotNil(ctx, "should have received new auth context")
	assert.Len(ctx.GetPrincipals(), 4, "should not have removed anything")
}

func TestMustNotIncludeFail(t *testing.T) {
	assert := assert.New(t)
	authz, _ := NewPrincipalFilter(PrincipalFilterConfig{
		MustNotIncludePrincipalGlob: "first.test1",
	})
	ctx, ok := authz.Authorize(authContext())
	assert.False(ok, "authorizer should have failed")
	assert.Nil(ctx, "should not have received new auth context")
}
