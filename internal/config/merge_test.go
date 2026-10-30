package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mergeBackend struct {
	Type    string
	Config  string
	Default bool
}

type mergeConf struct {
	Attrs    []string
	Backends []mergeBackend
	Options  map[string]string
	Name     string
}

func newMergeDefaults() *mergeConf {
	return &mergeConf{
		Attrs:    []string{"cn", "displayName"},
		Backends: []mergeBackend{{Type: "authfile", Config: "authfile", Default: true}},
		Options:  map[string]string{"a": "1", "b": "2"},
		Name:     "default",
	}
}

// These semantics come from github.com/mitchellh/mapstructure v1 and are
// relied on by existing configurations. The test passes unchanged against the
// pre-v2 code.
func TestMergeSemantics(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want func(*mergeConf)
	}{
		{"unset keeps defaults", `name: x`, func(c *mergeConf) { c.Name = "x" }},
		{"shorter list overlays the default", `attrs: [sAMAccountName]`, func(c *mergeConf) {
			c.Attrs = []string{"sAMAccountName", "displayName"}
		}},
		{"equal length replaces", `attrs: [uid, mail]`, func(c *mergeConf) { c.Attrs = []string{"uid", "mail"} }},
		{"longer list replaces", `attrs: [a, b, c]`, func(c *mergeConf) { c.Attrs = []string{"a", "b", "c"} }},
		{"empty list keeps the default", `attrs: []`, func(*mergeConf) {}},
		{"struct list elements are merged", `backends: [{type: authldap, config: ldap}]`, func(c *mergeConf) {
			c.Backends = []mergeBackend{{Type: "authldap", Config: "ldap", Default: true}}
		}},
		{"struct list grows", `backends: [{type: authldap, config: ldap}, {type: authoidc, config: oidc}]`, func(c *mergeConf) {
			c.Backends = []mergeBackend{{Type: "authldap", Config: "ldap", Default: true}, {Type: "authoidc", Config: "oidc"}}
		}},
		{"maps are merged", `options: {b: "3", c: "4"}`, func(c *mergeConf) {
			c.Options = map[string]string{"a": "1", "b": "3", "c": "4"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			globalConfig = map[string]any{}
			t.Cleanup(func() { globalConfig = map[string]any{} })
			require.NoError(t, LoadBytes([]byte("merge:\n  "+tc.yaml+"\n")))
			SetDefault("merge", newMergeDefaults())

			got, err := Get("merge")
			require.NoError(t, err)
			want := newMergeDefaults()
			tc.want(want)
			assert.Equal(t, want, got)
		})
	}
}
