package signatures

import (
	"fmt"
	"path/filepath"

	"brave_signer/internal/config"
	internalkeys "brave_signer/internal/keys"
	"brave_signer/internal/logger"
	internalsignatures "brave_signer/internal/signatures"
	"brave_signer/internal/utils"

	"github.com/spf13/cobra"
)

// SignFileConfig holds the configuration for signing a file.
type SignFileConfig struct {
	SignatureConfig `mapstructure:",squash"`

	PrivKeyPath string `mapstructure:"priv-key-path"`
	SignerID    string `mapstructure:"signer-id"`
}

func newSignFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "signfile",
		Short: "Sign a file.",
		Long: `Sign a file using an Ed25519 private key.

The command writes the signature package to a .sig file next to the signed file.
You'll be asked for a passphrase to decrypt the private key.

Process:
1. Load and decrypt the private key.
2. Hash the file using the selected hash algorithm.
3. Sign the file hash.
4. Write the signature package to a .sig file.`,
		Args: cobra.NoArgs,
		RunE: runSignFile,
	}

	addSignFileFlags(cmd)

	return cmd
}

func addSignFileFlags(cmd *cobra.Command) {
	cmd.Flags().String(
		"priv-key-path",
		"priv_key.pem",
		"Path to your Ed25519 private key in PEM format.",
	)

	cmd.Flags().String(
		"signer-id",
		"",
		"Signer's name or identifier.",
	)
}

func runSignFile(cmd *cobra.Command, args []string) error {
	logger.Info("Starting signing process...")

	cfg, err := loadSignFileConfig()
	if err != nil {
		return err
	}

	if err := validateSignFileConfig(cfg); err != nil {
		return err
	}

	return signFile(cfg)
}

func loadSignFileConfig() (SignFileConfig, error) {
	var cfg SignFileConfig

	if err := config.Unmarshal(&cfg); err != nil {
		return SignFileConfig{}, fmt.Errorf("load signfile config: %w", err)
	}

	return cfg, nil
}

func validateSignFileConfig(cfg SignFileConfig) error {
	if err := validateSignatureConfig(cfg.SignatureConfig); err != nil {
		return err
	}

	if cfg.PrivKeyPath == "" {
		return fmt.Errorf("private key path is required")
	}

	if err := validateSignerID(cfg.SignerID); err != nil {
		return err
	}

	return nil
}

func signFile(cfg SignFileConfig) error {
	fullFilePath, fullPrivKeyPath, err := resolveSignFilePaths(cfg)
	if err != nil {
		return err
	}

	privateKey, err := loadSigningPrivateKey(fullPrivKeyPath)
	if err != nil {
		return err
	}

	_, digest, err := hashFile(fullFilePath, cfg.HashAlgo)
	if err != nil {
		return err
	}

	signaturePath, err := createAndSaveSignature(fullFilePath, digest, cfg.SignerID, privateKey)
	if err != nil {
		return err
	}

	logSigningSuccess(fullFilePath, signaturePath)

	return nil
}

func resolveSignFilePaths(cfg SignFileConfig) (string, string, error) {
	fullFilePath, err := utils.ResolveExistingFile(cfg.FilePath)
	if err != nil {
		return "", "", fmt.Errorf("process file path: %w", err)
	}

	fullPrivKeyPath, err := utils.ResolveExistingFile(cfg.PrivKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("process private key path: %w", err)
	}

	return fullFilePath, fullPrivKeyPath, nil
}

func loadSigningPrivateKey(path string) (*internalkeys.PrivateKey, error) {
	privateKey, err := internalkeys.LoadPrivateFromPEMFile(path)
	if err != nil {
		return nil, fmt.Errorf("load private key from PEM file: %w", err)
	}

	return privateKey, nil
}

func createAndSaveSignature(
	filePath string,
	digest []byte,
	signerID string,
	privateKey *internalkeys.PrivateKey,
) (string, error) {
	signatureBytes, err := privateKey.SignMessage(digest)
	if err != nil {
		return "", fmt.Errorf("sign digest: %w", err)
	}

	signature, err := internalsignatures.New(signatureBytes)
	if err != nil {
		return "", fmt.Errorf("create signature: %w", err)
	}

	signature, err = signature.GeneratePackage(signerID)
	if err != nil {
		return "", fmt.Errorf("create signature package: %w", err)
	}

	signaturePath, err := signature.SaveToSIGFile(filePath)
	if err != nil {
		return "", fmt.Errorf("save signature to file: %w", err)
	}

	return signaturePath, nil
}

func logSigningSuccess(filePath string, signaturePath string) {
	logger.Info(fmt.Sprintf("Signature generation successful for file: %s", filepath.Base(filePath)))
	logger.Info(fmt.Sprintf(".sig file created at: %s", signaturePath))
}

// validateSignerID checks that the signer identifier is a reasonable length.
func validateSignerID(signerID string) error {
	const (
		minSignerInfoLength = 1
		maxSignerInfoLength = 65535
	)

	if len(signerID) < minSignerInfoLength || len(signerID) > maxSignerInfoLength {
		return fmt.Errorf(
			"signer information must be between %d and %d characters",
			minSignerInfoLength,
			maxSignerInfoLength,
		)
	}

	return nil
}
