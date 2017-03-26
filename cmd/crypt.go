package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/howeyc/gopass"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
)

// serverCmd represents the server command
var cryptCmd = &cobra.Command{
	Use:   "crypt",
	Short: "Make password hash for the authfile backend",
	Long:  "Make password hash for the authfile backend",
	RunE: func(cmd *cobra.Command, args []string) error {
		prompt := "Password to be hashed: "
		ret, _ := gopass.GetPasswdPrompt(prompt, true, os.Stdin, os.Stderr)
		fmt.Fprintf(os.Stderr, "\033[F%s%s\n", prompt, strings.Repeat(" ", len(ret)))
		hash, _ := bcrypt.GenerateFromPassword(ret, bcrypt.DefaultCost)
		fmt.Printf("%s\n", hash)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(cryptCmd)
}
