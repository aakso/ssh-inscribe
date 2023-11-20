package config

import (
	"os"
	"strings"

	"github.com/mitchellh/copystructure"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"

	"gopkg.in/yaml.v3"
)

var globalConfig map[string]interface{} = make(map[string]interface{})
var globalDefaults map[string]interface{} = make(map[string]interface{})

func LoadConfig(loc string) error {
	data, err := os.ReadFile(loc)
	if err != nil {
		return errors.Wrap(err, "cannot load configuration")
	}
	return LoadBytes(data)
}

func LoadBytes(data []byte) error {
	err := yaml.Unmarshal(data, &globalConfig)
	if err != nil {
		return errors.Wrap(err, "cannot parse configuration")
	}
	return nil
}

// Get value by section and merge defaults
func Get(section string) (interface{}, error) {
	val := getLoaded(section)
	def := GetDefault(section)
	switch {
	case val == nil && def == nil:
		return nil, errors.Errorf("section not found: %s", section)
	case val != nil && def == nil:
		return val, nil
	}
	decoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		Result:           def,
	})
	if err := decoder.Decode(val); err != nil {
		return nil, errors.Errorf("error while parsing section: %s", section)
	}
	return def, nil
}

// Return submap with key "section1.section2"
func getLoaded(section string) interface{} {
	return findValue(strings.Split(section, "."), globalConfig)
}
func findValue(remaining []string, conf map[string]interface{}) interface{} {
	section := remaining[0]
	val, ok := conf[section]
	if !ok {
		return nil
	}
	if mapval, ok := val.(map[string]interface{}); ok && len(remaining) > 1 {
		return findValue(remaining[1:], mapval)
	}
	return val
}

func SetDefault(path string, defaults interface{}) {
	p := strings.Split(path, ".")
	setDefault(p, globalDefaults, defaults)
}

func setDefault(remaining []string, conf map[string]interface{}, defaults interface{}) {
	section := remaining[0]
	val, ok := conf[section]
	if !ok {
		val = make(map[string]interface{})
		conf[section] = val
	}
	mapval, ok := val.(map[string]interface{})
	if !ok {
		mapval = make(map[string]interface{})
		conf[section] = mapval
	}
	if len(remaining) > 1 {
		setDefault(remaining[1:], mapval, defaults)
	} else {
		conf[section] = defaults
	}
}

func GetDefault(section string) interface{} {
	tmp := findValue(strings.Split(section, "."), globalDefaults)
	if tmp == nil {
		return nil
	}
	copy, err := copystructure.Copy(tmp)
	if err != nil {
		return nil
	}
	return copy
}

func GetAllDefaults() map[string]interface{} {
	copy, err := copystructure.Copy(globalDefaults)
	if err != nil {
		return nil
	}
	ret, _ := copy.(map[string]interface{})
	return ret
}
