package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"
)

var SshCmd = &cobra.Command{
	Use:                "ssh",
	Short:              "Invoke ssh command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if os.Getenv("SSH_AUTH_SOCK") == "" {
			if err := startAdhocAgent(); err != nil {
				return err
			}
			os.Setenv("SSH_AUTH_SOCK", agentSock)
		}
		ClientConfig.GenerateKeypair = true
		c := &client.Client{Config: ClientConfig}
		if err := c.Login(); err != nil {
			return err
		}
		c.Close()
		runSSH(RootCmd.Flags().Args()[2:])
		if agentListener != nil {
			agentListener.Close()
			wg.Wait()
		}
		return nil
	},
}
var agentListener net.Listener
var agentSock = path.Join(os.Getenv("HOME"), ".ssh_inscribe", "adhocagent.sock")
var wg = new(sync.WaitGroup)
var Log = logging.GetLogger("ssh").WithField("pkg", "cmd/ssh")

func startAdhocAgent() error {
	if _, err := os.Stat(agentSock); err == nil {
		if err := os.Remove(agentSock); err != nil {
			return errors.Wrapf(err, "cannot remove existing agent socket: %s", agentSock)
		}
	}
	ln, err := net.Listen("unix", agentSock)
	agentListener = ln
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
						return
					}
				}
				Log.WithError(err).Error("Accept error")
			}
			Log.Debug("New connection")
			go func(conn net.Conn) {
				defer wg.Done()
				if err := agent.ServeAgent(keyRing, conn); err != nil && err != io.EOF {
					Log.WithError(err).Error("Agent error")
				}
				Log.Debug("Connection closed")
			}(conn)
			wg.Add(1)
		}
	}()
	wg.Add(1)
	Log.Debug("agent started")
	return nil
}

func runSSH(args []string) error {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		return errors.New("ssh binary not found")
	}
	proc := exec.Command(bin, args...)
	proc.Stdin = os.Stdin
	proc.Stdout = os.Stdout
	proc.Stderr = os.Stderr
	if err := proc.Run(); err != nil {
		return err
	}
	return nil
}

// Hacky way to match flags before this subcommand to allow global flags to be set
// There seems to be no way of doing this in Cobra at the moment
func flagInit() {
	var cmdIndex int
	for i, arg := range os.Args {
		if strings.ToLower(SshCmd.Name()) == arg {
			cmdIndex = i
		}
	}
	// Inject -- after the subcommand to signal Cobra not to try to parse flags
	var args []string
	args = append(args, os.Args[:cmdIndex+1]...)
	args = append(args, "--")
	args = append(args, os.Args[cmdIndex+1:]...)
	if err := RootCmd.ParseFlags(args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	rootInit()
}

func init() {
	RootCmd.AddCommand(SshCmd)
	cobra.OnInitialize(flagInit)
}
