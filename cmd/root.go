package cmd

import (
	"brave-signer/cmd/keys"
	"brave-signer/cmd/signatures"
	"brave-signer/internal/config"

	"github.com/spf13/cobra"
)

func RootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "brave-signer",
		Short:         "Generate key pairs, sign files, and verify signatures.",
		Long:          rootLong,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().String("config-file-name", "config", "Config file name.")
	rootCmd.PersistentFlags().String("config-file-type", "yaml", "Config file type.")
	rootCmd.PersistentFlags().String("config-path", ".", "Config file location.")

	keys.Init(rootCmd, withConfig)
	signatures.Init(rootCmd, withConfig)

	rootCmd.AddCommand(versionCmd())
	rootCmd.AddCommand(genDocsCmd(rootCmd))

	return rootCmd
}

func withConfig(cmd *cobra.Command) {
	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		return config.LoadConfig(cmd)
	}
}

const rootLong = `brave-signer is a CLI tool for cryptographic signing operations.

Features:
- Generate Ed25519 key pairs and store them in PEM files.
- Encrypt private keys using Argon2-based key derivation.
- Sign files and create .sig files.
- Verify file signatures for authenticity and integrity.`
