package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/aakso/ssh-inscribe/pkg/config"
	"github.com/aakso/ssh-inscribe/pkg/logging"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var cfgFile string
var defaultCfgLoc string = path.Join(os.Getenv("HOME"), ".ssh_inscribe/config.yaml")

var RootCmd = &cobra.Command{
	Use:   "ssh-inscribe",
	Short: "SSH Inscribe - Secure CA",
	Long:  "",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(rootInit)
	RootCmd.PersistentFlags().StringVar(
		&cfgFile,
		"config",
		defaultCfgLoc,
		"config file",
	)
}

func rootInit() {
	if cfgFile != "" { // enable ability to specify config file via flag
		err := config.LoadConfig(cfgFile)
		if os.IsNotExist(errors.Cause(err)) && cfgFile == defaultCfgLoc {
			return
		}
		if err != nil {
			fmt.Println("foo")
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := logging.Setup(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
