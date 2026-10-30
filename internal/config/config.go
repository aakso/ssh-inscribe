package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/mitchellh/copystructure"
	"sigs.k8s.io/yaml"
)

var globalConfig = make(map[string]any)
var globalDefaults = make(map[string]any)

func LoadConfig(loc string) error {
	data, err := os.ReadFile(loc) //nolint:gosec // configuration file chosen by the administrator
	if err != nil {
		return fmt.Errorf("cannot load configuration: %w", err)
	}
	return LoadBytes(data)
}

func LoadBytes(data []byte) error {
	err := yaml.Unmarshal(data, &globalConfig)
	if err != nil {
		return fmt.Errorf("cannot parse configuration: %w", err)
	}
	return nil
}

// Get value by section and merge defaults
func Get(section string) (any, error) {
	val := getLoaded(section)
	def := GetDefault(section)
	switch {
	case val == nil && def == nil:
		return nil, fmt.Errorf("section not found: %s", section)
	case val != nil && def == nil:
		return val, nil
	}
	decoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		WeaklyTypedInput: true,
		Result:           def,
		DecodeHook:       legacySliceOverlay,
	})
	if err := decoder.Decode(val); err != nil {
		return nil, fmt.Errorf("error while parsing section: %s", section)
	}
	return def, nil
}

// legacySliceOverlay keeps the list semantics of github.com/mitchellh/mapstructure,
// which existing configurations depend on: a configured list is decoded onto
// the default list element by element, so a list shorter than the default
// keeps the remaining default elements (and an empty list keeps the
// default). github.com/go-viper/mapstructure/v2 truncates instead.
//
// For example the authldap default userSearchGetAttributes is [cn,
// displayName]; a configured [sAMAccountName] has always meant
// [sAMAccountName, displayName].
func legacySliceOverlay(from, to reflect.Value) (any, error) {
	data := from.Interface()
	for to.Kind() == reflect.Pointer || to.Kind() == reflect.Interface {
		if to.IsNil() {
			return data, nil
		}
		to = to.Elem()
	}
	if to.Kind() != reflect.Slice || to.IsNil() {
		return data, nil
	}
	if from.Kind() != reflect.Slice && from.Kind() != reflect.Array {
		return data, nil
	}
	if from.Len() >= to.Len() {
		return data, nil
	}
	merged := make([]any, to.Len())
	for i := range merged {
		if i < from.Len() {
			merged[i] = from.Index(i).Interface()
		} else {
			merged[i] = to.Index(i).Interface()
		}
	}
	return merged, nil
}

// Return submap with key "section1.section2"
func getLoaded(section string) any {
	return findValue(strings.Split(section, "."), globalConfig)
}
func findValue(remaining []string, conf map[string]any) any {
	section := remaining[0]
	val, ok := conf[section]
	if !ok {
		return nil
	}
	if mapval, ok := val.(map[string]any); ok && len(remaining) > 1 {
		return findValue(remaining[1:], mapval)
	}
	return val
}

func SetDefault(path string, defaults any) {
	p := strings.Split(path, ".")
	setDefault(p, globalDefaults, defaults)
}

func setDefault(remaining []string, conf map[string]any, defaults any) {
	section := remaining[0]
	val, ok := conf[section]
	if !ok {
		val = make(map[string]any)
		conf[section] = val
	}
	mapval, ok := val.(map[string]any)
	if !ok {
		mapval = make(map[string]any)
		conf[section] = mapval
	}
	if len(remaining) > 1 {
		setDefault(remaining[1:], mapval, defaults)
	} else {
		conf[section] = defaults
	}
}

func GetDefault(section string) any {
	tmp := findValue(strings.Split(section, "."), globalDefaults)
	if tmp == nil {
		return nil
	}
	c, err := copystructure.Copy(tmp)
	if err != nil {
		return nil
	}
	return c
}

func GetAllDefaults() map[string]any {
	c, err := copystructure.Copy(globalDefaults)
	if err != nil {
		return nil
	}
	ret, _ := c.(map[string]any)
	return ret
}
