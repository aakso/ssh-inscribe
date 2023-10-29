package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/aakso/ssh-inscribe/internal/globals"
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
