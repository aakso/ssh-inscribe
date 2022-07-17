package cmd

import (
	"fmt"
	"os"

	"github.com/aakso/ssh-inscribe/pkg/client"

	"github.com/aakso/ssh-inscribe/pkg/globals"
	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show server version",
	Long:  "Show server version",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &client.Client{Config: ClientConfig}
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
	ValidArgsFunction: cobra.NoFileCompletions,
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
