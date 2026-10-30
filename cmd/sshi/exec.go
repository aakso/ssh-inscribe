package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/internal/filteringagent"
	"github.com/aakso/ssh-inscribe/internal/logging"
	"github.com/aakso/ssh-inscribe/internal/ui"
	"github.com/aakso/ssh-inscribe/internal/util"
)

const (
	DefaultWindowsAdhocAgentListener = `\\.\pipe\sshi-adhoc-%s`
)

var ExecCmd = &cobra.Command{
	Use:                "exec",
	Short:              "Invoke any command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	ValidArgsFunction:  cobra.NoFileCompletions,
	RunE: func(_ *cobra.Command, _ []string) error {
		ignoreFlagsAfter("exec")
		return runExecCommand(RootCmd.Flags().Args()[2:])
	},
}
var (
	agentFilter = true
	Log         = logging.GetLogger("exec").WithField("pkg", "cmd/exec")
)

func runExecCommand(args []string) error {
	var (
		ln  net.Listener
		err error
	)
	authSockName := os.Getenv("SSH_AUTH_SOCK")
	var adHocAgentSock string
	if authSockName == "" || agentFilter {
		switch runtime.GOOS {
		case "windows":
			adHocAgentSock = fmt.Sprintf(DefaultWindowsAdhocAgentListener, util.RandB64(16))
			ln, err = util.LocalListen(adHocAgentSock)
			if err != nil {
				return err
			}
		default:
			// A private directory keeps other local users away from the
			// socket path between creation and listen.
			dir, err := os.MkdirTemp("", "sshi-")
			if err != nil {
				return err
			}
			defer func() {
				_ = os.RemoveAll(dir)
			}()
			adHocAgentSock = filepath.Join(dir, "agent.sock")
			ln, err = util.LocalListen(adHocAgentSock)
			if err != nil {
				return err
			}
		}
		Log.WithField("listener", ln.Addr()).Debug("started adhoc agent listener")
	}
	var adhoc *adhocAgent
	defer func() {
		switch {
		case adhoc != nil:
			adhoc.Close()
		case ln != nil:
			_ = ln.Close()
		}
	}()
	if authSockName == "" {
		adhoc = startAdhocAgent(ln, agent.NewKeyring())
		if err := os.Setenv("SSH_AUTH_SOCK", adHocAgentSock); err != nil {
			return err
		}
	}
	ClientConfig.GenerateKeypair = true
	c := &ui.Client{Config: ClientConfig}
	defer c.Close()
	if err := c.Login(); err != nil {
		return err
	}
	ca, err := c.GetCA()
	if err != nil {
		return err
	}
	if authSockName != "" && agentFilter {
		c.Close()
		conn, err := util.DialAuthSock(authSockName)
		if err != nil {
			return fmt.Errorf("could not connect to ssh-agent: %w", err)
		}
		defer func() {
			_ = conn.Close()
		}()
		targetAgent := agent.NewClient(conn)
		adhoc = startAdhocAgent(ln, filteringagent.New(
			targetAgent,
			ca,
			util.SignatureFormatFromSigningOptionAndCA(c.Config.SigningOption, ca),
			"ssh-"+ClientConfig.GenerateKeypairType))
		if err := os.Setenv("SSH_AUTH_SOCK", adHocAgentSock); err != nil {
			return err
		}
	}
	return runCommand(args)
}

// adhocAgent serves an agent on a local listener while a command runs.
type adhocAgent struct {
	ln   net.Listener
	impl agent.Agent
	log  *logrus.Entry
	wg   sync.WaitGroup

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

func startAdhocAgent(ln net.Listener, impl agent.Agent) *adhocAgent {
	a := &adhocAgent{
		ln:    ln,
		impl:  impl,
		log:   Log.WithField("worker", "adhocAgent"),
		conns: map[net.Conn]struct{}{},
	}
	a.wg.Go(a.accept)
	a.log.Debug("agent started")
	return a
}

func (a *adhocAgent) accept() {
	for {
		conn, err := a.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				a.log.Debug("shutting down")
				return
			}
			a.log.WithError(err).Error("accept error")
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !a.track(conn) {
			_ = conn.Close()
			continue
		}
		a.wg.Go(func() { a.serve(conn) })
	}
}

func (a *adhocAgent) track(conn net.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return false
	}
	a.conns[conn] = struct{}{}
	return true
}

func (a *adhocAgent) serve(conn net.Conn) {
	log := a.log.WithField("action", "connection")
	log.Debug("new connection")
	defer func() {
		a.mu.Lock()
		delete(a.conns, conn)
		a.mu.Unlock()
		_ = conn.Close()
	}()
	// Closed by Close: net.ErrClosed for sockets, os.ErrClosed for Windows pipes
	err := agent.ServeAgent(a.impl, conn)
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
		log.WithError(err).Error("agent error")
	}
	log.Debug("connection closed")
}

// Close stops the agent. Connections still open, e.g. held by a background
// ssh master process, are closed rather than waited for.
func (a *adhocAgent) Close() {
	a.mu.Lock()
	a.closed = true
	conns := make([]net.Conn, 0, len(a.conns))
	for c := range a.conns {
		conns = append(conns, c)
	}
	a.mu.Unlock()

	_ = a.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
	a.wg.Wait()
}

func runCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("no command")
	}

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("%s binary not found", args[0])
	}
	proc := exec.CommandContext(context.Background(), bin, args[1:]...) //nolint:gosec // running the user supplied command is the purpose of sshi exec/ssh
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	if err := proc.Run(); err != nil {
		return err
	}
	return nil
}

func init() {
	RootCmd.AddCommand(ExecCmd)
}
