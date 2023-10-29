package main

import (
	"fmt"
	"os"
	"path"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/aakso/ssh-inscribe/internal/config"
	"github.com/aakso/ssh-inscribe/internal/logging"
)

var cfgFile string
var defaultCfgLoc string = path.Join(os.Getenv("HOME"), ".ssh_inscribe/config.yaml")

var RootCmd = &cobra.Command{
	Use:   "ssh-inscribe",
	Short: "SSH Inscribe - SSH CA Server",
	Long:  "",
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
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := logging.Setup(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
