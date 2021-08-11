package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/aakso/ssh-inscribe/pkg/client"
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
	Use:   "add [caKeyFile]",
	Short: "Add CA private key from file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			ClientConfig.CAKeyFile = args[0]
		}
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		return c.AddCA()
	},
}

var ResponseCmd = &cobra.Command{
	Use:   "response",
	Short: "Send a response to a CA challenge in order to decrypt and add the CA key",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		return c.ChallengeResponse()
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

	AddCaCmd.Flags().BoolVarP(&ClientConfig.CAChallenge, "challenge", "c", false,
		"Use challenge mode to decrypt an encrypted private key")

	CaCmd.AddCommand(AddCaCmd)
	CaCmd.AddCommand(ResponseCmd)
}
