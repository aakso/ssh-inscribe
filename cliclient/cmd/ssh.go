package cmd

import (
	"github.com/spf13/cobra"
)

var SshCmd = &cobra.Command{
	Use:                "ssh",
	Short:              "Invoke ssh command with signed certificate on ssh-agent",
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		ignoreFlagsAfter("ssh")
		return runExecCommand(RootCmd.Flags().Args()[1:])
	},
}

func init() {
	RootCmd.AddCommand(SshCmd)
}
