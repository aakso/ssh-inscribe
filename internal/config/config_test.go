package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var loadConf []byte = []byte(
	`
test1:
  test2:
    test3:
      firstfield: overridden
  test-123:
    foo: bar
`)

type testConf struct {
	FirstField  string
	SecondField int
}

var testDefaults *testConf = &testConf{
	FirstField:  "test",
	SecondField: 123,
}

func TestApplyDefaults(t *testing.T) {
	assert := assert.New(t)
	SetDefault("test1.test2.test3", testDefaults)
	tmp, _ := GetDefault("test1.test2.test3").(*testConf)
	if assert.NotNil(tmp) {
		assert.Equal("test", tmp.FirstField)
		assert.Equal(123, tmp.SecondField)
	}
}

func TestLoadConfig(t *testing.T) {
	assert := assert.New(t)
	err := LoadBytes(loadConf)
	if assert.NoError(err) {
		fmt.Println(globalConfig)
		val, err := Get("test1.test2.test3")
		if assert.NoError(err) {
			conf, _ := val.(*testConf)
			assert.NotNil(conf)
			assert.Equal("overridden", conf.FirstField)
			assert.Equal(123, conf.SecondField)
		}
	}
}
