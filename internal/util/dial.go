package util

import (
	"context"
	"net"
	"time"
)

// DialTimeout bounds connecting to local ssh-agent sockets.
const DialTimeout = 5 * time.Second

// DialUnix connects to the unix socket at name.
func DialUnix(name string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DialTimeout)
	defer cancel()
	return (&net.Dialer{}).DialContext(ctx, "unix", name)
}
