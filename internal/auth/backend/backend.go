package backend

import (
	"fmt"

	"github.com/aakso/ssh-inscribe/internal/auth"
)

type Factory func(configsection string) (auth.Authenticator, error)

var backends = make(map[string]Factory)

func RegisterBackend(typ string, factory Factory) {
	backends[typ] = factory
}

func GetBackend(typ string, configsection string) (auth.Authenticator, error) {
	if factory, ok := backends[typ]; ok {
		return factory(configsection)
	}
	return nil, fmt.Errorf("unknown auth backend %s", typ)
}
