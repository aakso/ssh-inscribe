package cmd

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func expandFilename(fn string) string {
	if strings.HasPrefix(fn, "~/") {
		if hd, err := os.UserHomeDir(); err == nil {
			fn = filepath.Join(hd, fn[2:])
		}
	}
	return fn
}

func sshKnownHostnames(in []byte) []string {
	var hosts, ret []string
	var err error
	for {
		_, hosts, _, _, in, err = ssh.ParseKnownHosts(in)
		if err != nil {
			break
		}
		for _, h := range hosts {
			if i := strings.IndexRune(h, ']'); i != -1 && strings.HasPrefix(h, "[") {
				h = h[1:i]
			}
			// Skip wildcards, negations, and hashed entries
			if !strings.ContainsAny(h, "*?!|") {
				ret = append(ret, h)
			}
		}
	}
	return ret
}

func sshHostnames(cmd *cobra.Command, args []string, toComplete string) (ret []string, compDir cobra.ShellCompDirective) {
	compDir = cobra.ShellCompDirectiveNoFileComp
	if len(args) != 0 {
		return
	}

	ssh := exec.CommandContext(cmd.Context(), "ssh", "-G", toComplete)
	stdout, err := ssh.StdoutPipe()
	if err != nil || ssh.Start() != nil {
		return
	}
	var fns []string
	s := bufio.NewScanner(stdout)
	for s.Scan() {
		flds := strings.Fields(s.Text())
		if len(flds) > 1 && (flds[0] == "globalknownhostsfile" || flds[0] == "userknownhostsfile") {
			// These seem to be output space separated, with no escaping, so we're out of luck with filenames containing spaces
			for _, fn := range flds[1:] {
				if fn = expandFilename(fn); fn != "" {
					fns = append(fns, fn)
				}
			}
		}
	}
	_ = ssh.Wait()

	buf := make([]byte, 1024*1024)
	for _, fn := range fns {
		if f, err := os.Open(fn); err == nil {
			n, err := f.Read(buf)
			_ = f.Close()
			if err == nil {
				ret = append(ret, sshKnownHostnames(buf[:n])...)
			}
		}
	}
	return
}

var SshCmd = &cobra.Command{
	Use:                "ssh",
	Short:              "Invoke ssh command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	ValidArgsFunction:  sshHostnames,
	RunE: func(cmd *cobra.Command, args []string) error {
		ignoreFlagsAfter("ssh")
		return runExecCommand(RootCmd.Flags().Args()[1:])
	},
}

func init() {
	RootCmd.AddCommand(SshCmd)
}
