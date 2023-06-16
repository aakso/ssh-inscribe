package cmd

import (
	"fmt"

	"github.com/aakso/ssh-inscribe/pkg/globals"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var versionCmd = &cobra.Command{
	Use:               "version",
	Short:             "Show server version",
	Long:              "Show server version",
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(globals.Version())
		return nil
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
