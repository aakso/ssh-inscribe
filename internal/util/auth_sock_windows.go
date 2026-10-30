package util

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strings"

	"github.com/Microsoft/go-winio"
)

func DialAuthSock(name string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if name == "" {
		name = os.Getenv("SSH_AUTH_SOCK")
	}
	// Windows has no SSH_AUTH_SOCK set by default, default to native agent
	if name == "" {
		name = `\\.\pipe\openssh-ssh-agent`
	}

	if strings.HasPrefix(name, `\\.\pipe`) { // Native ssh-agent
		conn, err = winio.DialPipe(name, nil)
		if err != nil {
			return nil, fmt.Errorf("could not connect to ssh-agent: %w", err)
		}
	} else { // Cygwin
		conn, err = net.Dial("unix", name)
		if err != nil {
			return nil, fmt.Errorf("could not connect to ssh-agent: %w", err)
		}
	}
	return conn, nil
}

func LocalListen(name string) (net.Listener, error) {
	cu, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("could not get current user: %w", err)
	}
	sddl := fmt.Sprintf("D:P(A;;GA;;;%s)", cu.Uid)
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{
		SecurityDescriptor: sddl,
	})
	if err != nil {
		return nil, fmt.Errorf("could not create a named pipe listener: %w", err)
	}
	return ln, nil
}

// CheckSocketPath is a no-op on Windows, named pipes are created with an
// explicit security descriptor.
func CheckSocketPath(name string) error {
	return nil
}
