package signatures

import (
	"errors"
	"fmt"
	"path/filepath"

	"brave_signer/internal/config"
	"brave_signer/internal/keys"
	"brave_signer/internal/logger"
	internalsignatures "brave_signer/internal/signatures"
	"brave_signer/internal/utils"

	"github.com/spf13/cobra"
)

// VerifyFileConfig holds the command-specific configuration for verifying a signature.
type VerifyFileConfig struct {
	SignatureConfig `mapstructure:",squash"`

	PubKeyPath string `mapstructure:"pub-key-path"`
}

func newVerifyFileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verifyfile",
		Short: "Verify the signature of a file.",
		Long: `Verify the digital signature of a file using an Ed25519 public key.

The command expects a signature file named "<original_filename>.sig" next to the file being verified.

Process:
1. Load the Ed25519 public key.
2. Read the signature from the .sig file.
3. Hash the file using the selected hash algorithm.
4. Verify the signature against the file hash.`,
		Args: cobra.NoArgs,
		RunE: runVerifyFile,
	}

	cmd.Flags().String(
		"pub-key-path",
		"pub_key.pem",
		"Path to the Ed25519 public key in PEM format.",
	)

	return cmd
}

func runVerifyFile(cmd *cobra.Command, args []string) error {
	logger.Info("Starting signature verification process...")

	cfg, err := loadVerifyFileConfig()
	if err != nil {
		return err
	}

	if err := validateSignatureConfig(cfg.SignatureConfig); err != nil {
		return err
	}

	if cfg.PubKeyPath == "" {
		return fmt.Errorf("public key path is required")
	}

	return verifyFile(cfg)
}

func loadVerifyFileConfig() (VerifyFileConfig, error) {
	var cfg VerifyFileConfig

	if err := config.Unmarshal(&cfg); err != nil {
		return VerifyFileConfig{}, fmt.Errorf("load verifyfile config: %w", err)
	}

	return cfg, nil
}

func verifyFile(cfg VerifyFileConfig) error {
	fullFilePath, fullPubKeyPath, err := resolveVerifyFilePaths(cfg)
	if err != nil {
		return err
	}

	publicKey, signature, err := loadVerificationInputs(fullFilePath, fullPubKeyPath)
	if err != nil {
		return err
	}

	hasher, digest, err := hashFile(fullFilePath, cfg.HashAlgo)
	if err != nil {
		return err
	}

	signerInfo, err := verifyDigest(signature, digest, publicKey, verificationContext{
		filePath:   fullFilePath,
		pubKeyPath: fullPubKeyPath,
		hashAlgo:   hasher.HashType.String(),
	})
	if err != nil {
		return err
	}

	logVerificationSuccess(fullFilePath, fullPubKeyPath, hasher.HashType.String(), publicKey, signerInfo)

	return nil
}

type verificationContext struct {
	filePath   string
	pubKeyPath string
	hashAlgo   string
}

func resolveVerifyFilePaths(cfg VerifyFileConfig) (string, string, error) {
	fullFilePath, err := utils.ResolveExistingFile(cfg.FilePath)
	if err != nil {
		return "", "", fmt.Errorf("process file path: %w", err)
	}

	fullPubKeyPath, err := utils.ResolveExistingFile(cfg.PubKeyPath)
	if err != nil {
		return "", "", fmt.Errorf("process public key path: %w", err)
	}

	return fullFilePath, fullPubKeyPath, nil
}

func loadVerificationInputs(
	filePath string,
	pubKeyPath string,
) (*keys.PublicKey, *internalsignatures.Signature, error) {
	publicKey, err := keys.LoadPublicFromPEMFile(pubKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load public key from PEM file: %w", err)
	}

	signature, err := internalsignatures.LoadRawFromSIGFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("load signature file, expected <file>.sig: %w", err)
	}

	return publicKey, signature, nil
}

func verifyDigest(
	signature *internalsignatures.Signature,
	digest []byte,
	publicKey *keys.PublicKey,
	ctx verificationContext,
) ([]byte, error) {
	signerInfo, err := signature.VerifyDigest(digest, publicKey)
	if err != nil {
		if errors.Is(err, internalsignatures.ErrSignatureMismatch) {
			return nil, fmt.Errorf(
				"signature verification failed for %q using public key %q and hash algorithm %q: signature does not match; possible causes: the file was changed after signing, the wrong public key was used, the wrong hash algorithm was selected, or the .sig file is corrupted/tampered",
				filepath.Base(ctx.filePath),
				filepath.Base(ctx.pubKeyPath),
				ctx.hashAlgo,
			)
		}

		return nil, fmt.Errorf("verify signature: %w", err)
	}

	return signerInfo, nil
}

func logVerificationSuccess(
	filePath string,
	pubKeyPath string,
	hashAlgo string,
	publicKey *keys.PublicKey,
	signerInfo []byte,
) {
	logger.Info(fmt.Sprintf("Verification successful for file: %s", filepath.Base(filePath)))
	logger.Info(fmt.Sprintf("Verified using public key: %s", filepath.Base(pubKeyPath)))
	logger.Info(fmt.Sprintf("Public key fingerprint (SHA-256): %s", publicKey.FingerprintBase64()))
	logger.Info(fmt.Sprintf("Hash algorithm: %s", hashAlgo))
	logger.Info(fmt.Sprintf("Signer info:\n%s", signerInfo))
}
