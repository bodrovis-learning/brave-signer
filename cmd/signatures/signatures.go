package signatures

import (
	"fmt"

	"brave_signer/internal/hashers"

	"github.com/spf13/cobra"
)

// SignatureConfig holds shared configuration for signature commands.
type SignatureConfig struct {
	FilePath string `mapstructure:"file-path"`
	HashAlgo string `mapstructure:"hash-algo"`
}

func newSignaturesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signatures",
		Short: "Create and verify signatures.",
		Long: `Create and verify digital signatures.

Available subcommands:
- signfile: Create a signature for a file.
- verifyfile: Verify a file signature.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	addFlags(cmd)

	cmd.AddCommand(newSignFileCmd())
	cmd.AddCommand(newVerifyFileCmd())

	return cmd
}

// Init initializes the signatures command and sets up its flags.
func Init(rootCmd *cobra.Command, withConfig func(*cobra.Command)) {
	cmd := newSignaturesCmd()

	withConfig(cmd)

	rootCmd.AddCommand(cmd)
}

func addFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String(
		"file-path",
		"",
		"Path to the file that should be signed or verified.",
	)

	cmd.PersistentFlags().String(
		"hash-algo",
		hashers.DefaultHasherName,
		"Hashing algorithm to use for signing and verification.",
	)
}

func validateSignatureConfig(cfg SignatureConfig) error {
	if cfg.FilePath == "" {
		return fmt.Errorf("file path is required")
	}

	if cfg.HashAlgo == "" {
		return fmt.Errorf("hash algorithm is required")
	}

	return nil
}

func hashFile(filePath string, hashAlgo string) (*hashers.Hasher, []byte, error) {
	hasher, err := hashers.New(hashAlgo)
	if err != nil {
		return nil, nil, fmt.Errorf("create hasher: %w", err)
	}

	digest, err := hasher.HashFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("hash file: %w", err)
	}

	return hasher, digest, nil
}
