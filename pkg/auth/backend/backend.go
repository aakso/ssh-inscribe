package backend

import (
	"fmt"

	"github.com/aakso/ssh-inscribe/pkg/auth"
	"github.com/pkg/errors"
)

type Factory func(configsection string) (auth.Authenticator, error)

var backends map[string]Factory = make(map[string]Factory)

func RegisterBackend(typ string, factory Factory) {
	backends[typ] = factory
}

func GetBackend(typ string, configsection string) (auth.Authenticator, error) {
	if factory, ok := backends[typ]; ok {
		return factory(configsection)
	}
	return nil, errors.New(fmt.Sprintf("unknown auth backend %s", typ))
}
