package cmd

import (
	"fmt"
	"strings"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

var principals []string

var CaCmd = &cobra.Command{
	Use:   "ca",
	Short: "CA key management",
}

var ShowCaCmd = &cobra.Command{
	Use:   "show",
	Short: "Show CA public key",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		caKey, err := c.GetCA()
		if err != nil {
			return err
		}
		if principals != nil {
			fmt.Printf(`cert-authority,principals="%s" %s`,
				strings.Join(principals, ","),
				ssh.MarshalAuthorizedKey(caKey),
			)
		} else {
			fmt.Printf("%s", ssh.MarshalAuthorizedKey(caKey))
		}
		return nil
	},
	ValidArgsFunction: noCompletion,
}

var AddCaCmd = &cobra.Command{
	Use:   "add",
	Short: "Add CA private key from file",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("specify ca key file")
		}
		ClientConfig.CAKeyFile = args[0]
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		return c.AddCA()
	},
}

func init() {
	RootCmd.AddCommand(CaCmd)
	CaCmd.AddCommand(ShowCaCmd)
	ShowCaCmd.Flags().StringArrayVarP(
		&principals,
		"principals",
		"p",
		nil,
		"Format ca public key with allowed principals for use with authorized_keys",
	)
	_ = ShowCaCmd.RegisterFlagCompletionFunc("principals", noCompletion)
	CaCmd.AddCommand(AddCaCmd)
}
