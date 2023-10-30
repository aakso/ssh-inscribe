package main

import (
	"fmt"

	"github.com/bgentry/speakeasy"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// serverCmd represents the server command
var cryptCmd = &cobra.Command{
	Use:               "crypt",
	Short:             "Make password hash for the authfile backend",
	Long:              "Make password hash for the authfile backend",
	Args:              cobra.NoArgs,
	ValidArgsFunction: cobra.NoFileCompletions,
	RunE: func(cmd *cobra.Command, args []string) error {
		prompt := "Password to be hashed: "
		ret, _ := speakeasy.Ask(prompt)
		hash, _ := bcrypt.GenerateFromPassword([]byte(ret), bcrypt.DefaultCost)
		fmt.Printf("%s\n", hash)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(cryptCmd)
}
