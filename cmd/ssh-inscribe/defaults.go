package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	_ "github.com/aakso/ssh-inscribe/internal/auth/backend/all"
	"github.com/aakso/ssh-inscribe/internal/config"
	_ "github.com/aakso/ssh-inscribe/internal/server"
)

// serverCmd represents the server command
var defaultsCmd = &cobra.Command{
	Use:               "defaults",
	Short:             "Print configuration defaults",
	Long:              `Print configuration defaults`,
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := yaml.Marshal(config.GetAllDefaults())
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	RootCmd.AddCommand(defaultsCmd)
}
