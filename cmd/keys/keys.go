package keys

import (
	"github.com/spf13/cobra"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage key pairs.",
		Long: `Manage Ed25519 public/private key pairs.

Available subcommands:
- generate: Generate a new Ed25519 key pair.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newGenerateCmd())

	return cmd
}

// Init initializes keys commands.
func Init(rootCmd *cobra.Command, withConfig func(*cobra.Command)) {
	cmd := newKeysCmd()

	withConfig(cmd)

	rootCmd.AddCommand(cmd)
}
