package cmd

import (
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"
)

var ExecCmd = &cobra.Command{
	Use:                "exec",
	Short:              "Invoke any command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ignoreFlagsAfter("exec")
		return runExecCommand(RootCmd.Flags().Args()[2:])
	},
}
var agentListener net.Listener
var wg = new(sync.WaitGroup)
var Log = logging.GetLogger("exec").WithField("pkg", "cmd/exec")

func runExecCommand(args []string) error {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		tmpFile, err := ioutil.TempFile(os.TempDir(), "sshi_adhocagent")
		if err != nil {
			return err
		}
		agentSock := tmpFile.Name()
		if err := startAdhocAgent(agentSock); err != nil {
			return err
		}
		os.Setenv("SSH_AUTH_SOCK", agentSock)
		defer func() {
			agentListener.Close()
			wg.Wait()
		}()
	}
	ClientConfig.GenerateKeypair = true
	c := &client.Client{Config: ClientConfig}
	defer c.Close()
	if err := c.Login(); err != nil {
		return err
	}
	return runCommand(args)
}

func startAdhocAgent(agentSock string) error {
	log := Log.WithField("worker", "adhocAgent")
	if _, err := os.Stat(agentSock); err == nil {
		if err := os.Remove(agentSock); err != nil {
			return errors.Wrapf(err, "cannot remove existing agent socket: %s", agentSock)
		}
	}
	prevUmask := syscall.Umask(0177)
	ln, err := net.Listen("unix", agentSock)
	agentListener = ln
	syscall.Umask(prevUmask)
	if err != nil {
		return errors.Wrapf(err, "cannot listen on socket: %s", agentSock)
	}
	go func() {
		keyRing := agent.NewKeyring()
		defer wg.Done()
		for {
			conn, err := agentListener.Accept()
			if err != nil {
				if operr, _ := err.(*net.OpError); operr != nil {
					if operr.Err.Error() == "use of closed network connection" {
						log.Debug("shutting down")
						return
					}
				}
				log.WithError(err).Error("accept error")
			}
			go func(conn net.Conn) {
				log := log.WithField("action", "connection")
				log.Debug("new connection")
				defer wg.Done()
				if err := agent.ServeAgent(keyRing, conn); err != nil && err != io.EOF {
					log.WithError(err).Error("agent error")
				}
				log.Debug("connection closed")
			}(conn)
			wg.Add(1)
		}
	}()
	wg.Add(1)
	log.Debug("agent started")
	return nil
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
