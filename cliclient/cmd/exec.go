package cmd

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/aakso/ssh-inscribe/pkg/filteringagent"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/aakso/ssh-inscribe/pkg/util"
)

const (
	DefaultWindowsAdhocAgentListener = `\\.\pipe\sshi-adhoc-%s`
)

var ExecCmd = &cobra.Command{
	Use:                "exec",
	Short:              "Invoke any command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	ValidArgsFunction:  cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		ignoreFlagsAfter("exec")
		return runExecCommand(RootCmd.Flags().Args()[2:])
	},
}
var (
	agentFilter = true
	wg          = new(sync.WaitGroup)
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
			tmpFile, err := ioutil.TempFile(os.TempDir(), "sshi_adhocagent")
			if err != nil {
				return err
			}
			adHocAgentSock = tmpFile.Name()
			ln, err = util.LocalListen(adHocAgentSock)
			if err != nil {
				return err
			}
		}
		Log.WithField("listener", ln.Addr()).Debug("started adhoc agent listener")

		defer func() {
			_ = ln.Close()
			wg.Wait()
		}()
	}
	if authSockName == "" {
		startAdhocAgent(ln, agent.NewKeyring())
		if err := os.Setenv("SSH_AUTH_SOCK", adHocAgentSock); err != nil {
			return err
		}
	}
	ClientConfig.GenerateKeypair = true
	c := &client.Client{Config: ClientConfig}
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
			return errors.Wrap(err, "could not connect to ssh-agent")
		}
		targetAgent := agent.NewClient(conn)
		startAdhocAgent(ln, filteringagent.New(
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

func startAdhocAgent(ln net.Listener, agentImpl agent.Agent) {
	log := Log.WithField("worker", "adhocAgent")
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					log.Debug("shutting down")
					return
				}
				log.WithError(err).Error("accept error")
			}
			go func(conn net.Conn) {
				log := log.WithField("action", "connection")
				log.Debug("new connection")
				defer wg.Done()
				if err := agent.ServeAgent(agentImpl, conn); err != nil && err != io.EOF {
					log.WithError(err).Error("agent error")
				}
				log.Debug("connection closed")
			}(conn)
			wg.Add(1)
		}
	}()
	wg.Add(1)
	log.Debug("agent started")
	return
}

func runCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("no command")
	}

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return errors.Errorf("%s binary not found", args[0])
	}
	proc := exec.Command(bin, args[1:]...)
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
