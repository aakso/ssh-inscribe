package main

import (
	"github.com/spf13/cobra"

	"github.com/aakso/ssh-inscribe/internal/server"
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
