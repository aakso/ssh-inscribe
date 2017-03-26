package cmd

import (
	"os"
	"time"

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
		}
		return c.Login()
	},
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

	var defExpire time.Duration
	if expire := os.Getenv("SSH_INSCRIBE_EXPIRE"); expire != "" {
		defExpire, _ = time.ParseDuration(expire)
	}
	ReqCmd.Flags().DurationVarP(
		&ClientConfig.CertLifetime,
		"expire",
		"e",
		defExpire,
		"Request specific lifetime. Example '10m' ($SSH_INSCRIBE_EXPIRE)",
	)
	if os.Getenv("SSH_INSCRIBE_WRITE") != "" {
		ClientConfig.WriteCert = true
	}
	ReqCmd.Flags().BoolVarP(
		&ClientConfig.WriteCert,
		"write",
		"w",
		ClientConfig.WriteCert,
		"Write certificate (and generated keys) to file specified by <identity> ($SSH_INSCRIBE_WRITE)",
	)

	if os.Getenv("SSH_INSCRIBE_RENEW") != "" {
		ClientConfig.AlwaysRenew = true
	}
	ReqCmd.Flags().BoolVar(
		&ClientConfig.AlwaysRenew,
		"renew",
		ClientConfig.AlwaysRenew,
		"Always renew the certificate even if it is not expired ($SSH_INSCRIBE_RENEW)",
	)

	if os.Getenv("SSH_INSCRIBE_USE_AGENT") == "0" {
		ClientConfig.UseAgent = false
	}
	ReqCmd.Flags().BoolVar(
		&ClientConfig.UseAgent,
		"agent",
		ClientConfig.UseAgent,
		"Store key and certificate to a ssh-agent specified by $SSH_AUTH_SOCK ($SSH_INSCRIBE_USE_AGENT)",
	)

	if os.Getenv("SSH_INSCRIBE_GENKEY") != "" {
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
}
