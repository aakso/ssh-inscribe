package cmd

import (
	"github.com/aakso/ssh-inscribe/pkg/server"
	"github.com/spf13/cobra"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:               "server",
	Short:             "Start ssh-inscribe server",
	Long:              `Start the service`,
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		if srv, err := server.Build(); err != nil {
			return err
		} else {
			return srv.Start()
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)
}
