package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/aakso/ssh-inscribe/pkg/client"
	"github.com/aakso/ssh-inscribe/pkg/logging"
)

var RootCmd = &cobra.Command{
	Use:           "sshi",
	Short:         "sshi connects to ssh-inscribed for SSH certificate generation",
	SilenceErrors: true,
	SilenceUsage:  true,
}
var ClientConfig = &client.Config{
	UseAgent:            true,
	Timeout:             2 * time.Second,
	Retries:             3,
	GenerateKeypairType: "rsa",
	GenerateKeypairSize: 2048,
}
var logLevel = "info"

func rootInit() {
	logging.Defaults.DefaultLevel = logLevel
	if err := logging.Setup(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Hacky way to match flags before this subcommand to allow global flags to be set
// There seems to be no way of doing this in Cobra at the moment
func ignoreFlagsAfter(cmds ...string) {
	ignoreFlags := map[string]bool{}
	for _, v := range cmds {
		ignoreFlags[v] = true
	}
	var cmdIndex int
	for i, arg := range os.Args {
		if ignoreFlags[strings.ToLower(arg)] {
			cmdIndex = i
		}
	}

	// Inject -- after the subcommand to signal Cobra not to try to parse flags
	var args []string
	args = append(args, os.Args[:cmdIndex+1]...)
	args = append(args, "--")
	args = append(args, os.Args[cmdIndex+1:]...)
	if err := RootCmd.ParseFlags(args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// Rerun rootinit to re-evaluate flag values
	rootInit()
}

func init() {
	cobra.OnInitialize(rootInit)
	RootCmd.PersistentFlags().StringVar(
		&ClientConfig.URL,
		"url",
		os.Getenv("SSH_INSCRIBE_URL"),
		"URL to ssh-inscribed ($SSH_INSCRIBE_URL)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("url", noCompletion)

	defTimeout := ClientConfig.Timeout
	if expire := os.Getenv("SSH_INSCRIBE_TIMEOUT"); expire != "" {
		defTimeout, _ = time.ParseDuration(expire)
	}
	RootCmd.PersistentFlags().DurationVar(
		&ClientConfig.Timeout,
		"timeout",
		defTimeout,
		"Client timeout ($SSH_INSCRIBE_TIMEOUT)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("timeout", noCompletion)

	retries := ClientConfig.Retries
	if os.Getenv("SSH_INSCRIBE_RETRIES") != "" {
		retries, _ = strconv.Atoi(os.Getenv("SSH_INSCRIBE_RETRIES"))
	}
	RootCmd.PersistentFlags().IntVar(
		&ClientConfig.Retries,
		"retries",
		retries,
		"Set retry on server failure ($SSH_INSCRIBE_RETRIES)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("retries", noCompletion)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_DEBUG")); err == nil && val {
		ClientConfig.Debug = true
	}
	RootCmd.PersistentFlags().BoolVar(
		&ClientConfig.Debug,
		"debug",
		ClientConfig.Debug,
		"Enable request level debugging (outputs sensitive data) ($SSH_INSCRIBE_DEBUG)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_INSECURE")); err == nil && val {
		ClientConfig.Insecure = true
	}
	RootCmd.PersistentFlags().BoolVar(
		&ClientConfig.Insecure,
		"insecure",
		ClientConfig.Insecure,
		"Disable TLS validation for the server connection (not recommended) ($SSH_INSCRIBE_INSECURE)",
	)

	if os.Getenv("SSH_INSCRIBE_LOGLEVEL") != "" {
		logLevel = os.Getenv("SSH_INSCRIBE_LOGLEVEL")
	}
	RootCmd.PersistentFlags().StringVar(
		&logLevel,
		"loglevel",
		logLevel,
		"Set logging level ($SSH_INSCRIBE_LOGLEVEL)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("loglevel", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return logging.GetAvailableLevelNames(), cobra.ShellCompDirectiveNoFileComp
	})

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_QUIET")); err == nil && val {
		ClientConfig.Quiet = true
	}
	RootCmd.PersistentFlags().BoolVarP(
		&ClientConfig.Quiet,
		"quiet",
		"q",
		ClientConfig.Quiet,
		"Set quiet mode ($SSH_INSCRIBE_QUIET)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_AGENT_CONFIRM")); err == nil && val {
		ClientConfig.AgentConfirm = true
	}
	RootCmd.PersistentFlags().BoolVar(
		&ClientConfig.AgentConfirm,
		"agent-confirm",
		ClientConfig.AgentConfirm,
		"Request confirm constraint when storing keys and certs to the agent ($SSH_INSCRIBE_AGENT_CONFIRM)",
	)

	if val, err := strconv.ParseBool(os.Getenv("SSH_INSCRIBE_AGENT_FILTER")); err == nil && !val {
		agentFilter = false
	}
	RootCmd.PersistentFlags().BoolVar(
		&agentFilter,
		"agent-filter",
		agentFilter,
		"sshi will setup an internal filtering agent for ssh and exec commands ($SSH_INSCRIBE_AGENT_FILTER)",
	)

	defLoginAuthEndpoints := []string{}
	if logins := os.Getenv("SSH_INSCRIBE_LOGIN_AUTH_ENDPOINTS"); logins != "" {
		defLoginAuthEndpoints = strings.Split(logins, ",")
	}
	RootCmd.PersistentFlags().StringSliceVarP(
		&ClientConfig.LoginAuthEndpoints,
		"login",
		"l",
		defLoginAuthEndpoints,
		"Login to specific auth endpoints ($SSH_INSCRIBE_LOGIN_AUTH_ENDPOINTS)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("login", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		c := &client.Client{
			Config: ClientConfig,
		}
		defer c.Close()
		discoverResult, err := c.GetAuthenticators()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		names := make([]string, len(discoverResult))
		for i, v := range discoverResult {
			names[i] = v.AuthenticatorName
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	})

	var defIncludePrincipals string
	if s := os.Getenv("SSH_INSCRIBE_INCLUDE_PRINCIPALS"); s != "" {
		defIncludePrincipals = s
	}
	RootCmd.PersistentFlags().StringVar(
		&ClientConfig.IncludePrincipals,
		"include",
		defIncludePrincipals,
		"Request only principals matching the glob pattern to be included ($SSH_INSCRIBE_INCLUDE_PRINCIPALS)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("include", noCompletion)

	var defExcludePrincipals string
	if s := os.Getenv("SSH_INSCRIBE_EXCLUDE_PRINCIPALS"); s != "" {
		defExcludePrincipals = s
	}
	RootCmd.PersistentFlags().StringVar(
		&ClientConfig.ExcludePrincipals,
		"exclude",
		defExcludePrincipals,
		"Request only principals not matching the glob pattern to be included ($SSH_INSCRIBE_EXCLUDE_PRINCIPALS)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("exclude", noCompletion)

	var defExpire time.Duration
	if expire := os.Getenv("SSH_INSCRIBE_EXPIRE"); expire != "" {
		defExpire, _ = time.ParseDuration(expire)
	}
	RootCmd.PersistentFlags().DurationVarP(
		&ClientConfig.CertLifetime,
		"expire",
		"e",
		defExpire,
		"Request specific lifetime. Example '10m' ($SSH_INSCRIBE_EXPIRE)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("expire", noCompletion)

	if kt := os.Getenv("SSH_INSCRIBE_GENKEY_TYPE"); kt != "" {
		ClientConfig.GenerateKeypairType = kt
	}
	RootCmd.PersistentFlags().StringVarP(
		&ClientConfig.GenerateKeypairType,
		"keytype",
		"t",
		ClientConfig.GenerateKeypairType,
		"Set ad-hoc keypair type. Valid values: rsa, ed25519 ($SSH_INSCRIBE_GENKEY_TYPE)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("keytype", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"rsa", "ed25519"}, cobra.ShellCompDirectiveNoFileComp
	})

	if ks := os.Getenv("SSH_INSCRIBE_GENKEY_SIZE"); ks != "" {
		size, _ := strconv.ParseInt(ks, 10, 0)
		ClientConfig.GenerateKeypairSize = int(size)
	}
	RootCmd.PersistentFlags().IntVarP(
		&ClientConfig.GenerateKeypairSize,
		"keysize",
		"b",
		ClientConfig.GenerateKeypairSize,
		"Set ad-hoc keypair size. Only valid for RSA keytype ($SSH_INSCRIBE_GENKEY_SIZE)",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("keysize", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var sizes []string
		if ClientConfig.GenerateKeypairType == "rsa" {
			// Opinionated set, non-exhaustive
			sizes = []string{"2048", "3072", "4096", "8192"}
		}
		return sizes, cobra.ShellCompDirectiveNoFileComp
	})

	if opt := os.Getenv("SSH_INSCRIBE_SIGNING_OPTION"); opt != "" {
		ClientConfig.SigningOption = opt
	}
	RootCmd.PersistentFlags().StringVarP(
		&ClientConfig.SigningOption,
		"signing-option",
		"o",
		ClientConfig.SigningOption,
		"Optional flag to be used in signing. This is only used if the CA's key is RSA. ($SSH_INSCRIBE_SIGNING_OPTION)\n"+
			"If not, this option is silently ignored. Valid values: rsa-sha2-256 and rsa-sha2-512",
	)
	_ = RootCmd.RegisterFlagCompletionFunc("signing-option", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"rsa-sha2-256", "rsa-sha2-512"}, cobra.ShellCompDirectiveNoFileComp
	})

	if opt := os.Getenv("SSH_INSCRIBE_MAX_PRINCIPALS_PER_CERTIFICATE"); opt != "" {
		iv, _ := strconv.ParseInt(opt, 10, 64)
		ClientConfig.MaxPrincipalsPerCertificate = int(iv)
	}
	RootCmd.PersistentFlags().IntVar(
		&ClientConfig.MaxPrincipalsPerCertificate,
		"max-principals-per-certificate",
		ClientConfig.MaxPrincipalsPerCertificate,
		"Optional flag that instructs the server to put maximum of N principals per signed certificate.",
	)
}
