package main

import (
	"fmt"
	"os"

	"github.com/aakso/ssh-inscribe/internal/ui"

	"github.com/spf13/cobra"

	"github.com/aakso/ssh-inscribe/internal/globals"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:               "version",
	Short:             "Show server version",
	Long:              "Show server version",
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &ui.Client{Config: ClientConfig}
		fmt.Printf("local: %s\n", globals.Version())

		if ClientConfig.URL == "" {
			return nil
		}
		if serverVer, err := c.GetServerVersion(); err == nil {
			fmt.Printf("server: %s\n", serverVer)
		} else {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
