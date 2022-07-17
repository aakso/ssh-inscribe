package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var CompletionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion script",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			return cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			return cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			return cmd.Root().GenPowerShellCompletion(os.Stdout)
		}
		return fmt.Errorf("unsupported shell: %s", args[0])
	},
	Args: cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var shells []string
		if len(args) == 0 {
			shells = []string{"bash", "zsh", "fish", "powershell"}
		}
		return shells, cobra.ShellCompDirectiveNoFileComp
	},
}

func init() {
	RootCmd.AddCommand(CompletionCmd)
}
