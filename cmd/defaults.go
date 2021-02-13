package cmd

import (
	"fmt"

	_ "github.com/aakso/ssh-inscribe/pkg/auth/backend/all"
	"github.com/aakso/ssh-inscribe/pkg/config"
	_ "github.com/aakso/ssh-inscribe/pkg/server"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// serverCmd represents the server command
var defaultsCmd = &cobra.Command{
	Use:   "defaults",
	Short: "Print configuration defaults",
	Long:  `Print configuration defaults`,
	RunE: func(cmd *cobra.Command, args []string) error {
		out, _ := yaml.Marshal(config.GetAllDefaults())
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	RootCmd.AddCommand(defaultsCmd)
}
