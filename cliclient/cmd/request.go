package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/spf13/cobra"
)

var ReqCmd = &cobra.Command{
	Use:   "req",
	Short: "Login to server and generate SSH certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		if b, _ := cmd.Flags().GetBool("clear"); b == true {
			return c.Logout()
		} else if b, _ := cmd.Flags().GetBool("list-logins"); b == true {
			discoverResult, err := c.GetAuthenticators()
			if err != nil {
				return err
			}
			for _, v := range discoverResult {
				fmt.Printf("%s (%s)\n", v.AuthenticatorName, v.AuthenticatorRealm)
			}
			return nil
		}
		return c.Login()
	},
	ValidArgsFunction: cobra.NoFileCompletions,
}

func init() {
	RootCmd.AddCommand(ReqCmd)
	ReqCmd.Flags().StringVarP(
		&ClientConfig.IdentityFile,
		"identity",
		"i",
		os.Getenv("SSH_INSCRIBE_IDENTITY"),
		"Identity (private key) file location. Required if --generate is unset ($SSH_INSCRIBE_IDENTITY)",
	)
	_ = ReqCmd.RegisterFlagCompletionFunc("identity", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if toComplete == "" {
			return []string{"~/.ssh/"}, cobra.ShellCompDirectiveNoSpace
		}
		return nil, cobra.ShellCompDirectiveDefault
	})

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_WRITE")); err == nil && val {
		ClientConfig.WriteCert = true
	}
	ReqCmd.Flags().BoolVarP(
		&ClientConfig.WriteCert,
		"write",
		"w",
		ClientConfig.WriteCert,
		"Write certificate (and generated keys) to file specified by <identity> ($SSH_INSCRIBE_WRITE)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_RENEW")); err == nil && val {
		ClientConfig.AlwaysRenew = true
	}
	ReqCmd.Flags().BoolVar(
		&ClientConfig.AlwaysRenew,
		"renew",
		ClientConfig.AlwaysRenew,
		"Always renew the certificate even if it is not expired ($SSH_INSCRIBE_RENEW)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_USE_AGENT")); err == nil && !val {
		ClientConfig.UseAgent = false
	}
	ReqCmd.Flags().BoolVar(
		&ClientConfig.UseAgent,
		"agent",
		ClientConfig.UseAgent,
		"Store key and certificate to a ssh-agent specified by $SSH_AUTH_SOCK ($SSH_INSCRIBE_USE_AGENT)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_GENKEY")); err == nil && val {
		ClientConfig.GenerateKeypair = true
	}
	ReqCmd.Flags().BoolVarP(
		&ClientConfig.GenerateKeypair,
		"generate",
		"g",
		ClientConfig.GenerateKeypair,
		"Generate ad-hoc keypair. Useful with ssh-agent ($SSH_INSCRIBE_GENKEY)",
	)

	ReqCmd.Flags().Bool(
		"clear",
		false,
		"Clear granted certificate",
	)

	ReqCmd.Flags().Bool(
		"list-logins",
		false,
		"List available auth endpoints",
	)
}
