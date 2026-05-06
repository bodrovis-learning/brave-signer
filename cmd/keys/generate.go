package keys

import (
	"fmt"
	"path/filepath"

	"brave-signer/internal/config"
	internalkeys "brave-signer/internal/keys"
	"brave-signer/internal/logger"

	"github.com/spf13/cobra"
)

// KeyGenConfig holds the command-specific configuration for key generation.
type KeyGenConfig struct {
	PrivKeyOutputPath    string `mapstructure:"priv-key-path"`
	PubKeyOutputPath     string `mapstructure:"pub-key-path"`
	SkipPEMPresenceCheck bool   `mapstructure:"skip-pem-presence-check"`

	Crypto internalkeys.KeyEncryptionConfig `mapstructure:"crypto"`
}

func newGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate an Ed25519 key pair.",
		Long: `Generate an Ed25519 key pair and store it in PEM files.

The private key is encrypted using a passphrase you enter.

Files created:
- Encrypted private key in PEM format.
- Public key in PEM format.`,
		Args: cobra.NoArgs,
		RunE: runGenerate,
	}

	addGenerateFlags(cmd)

	return cmd
}

func addGenerateFlags(cmd *cobra.Command) {
	cmd.Flags().String(
		"pub-key-path",
		"pub_key.pem",
		"Path to save the public key in PEM format.",
	)

	cmd.Flags().String(
		"priv-key-path",
		"priv_key.pem",
		"Path to save the private key in PEM format.",
	)

	cmd.Flags().Bool(
		"skip-pem-presence-check",
		false,
		"Skip checking if keys already exist. This may overwrite keys.",
	)

	cmd.Flags().Int(
		"crypto.salt-size",
		16,
		"Salt size in bytes used for key derivation.",
	)

	cmd.Flags().Uint32(
		"crypto.argon2-time",
		1,
		"Time parameter for the Argon2id key derivation function.",
	)

	cmd.Flags().Uint32(
		"crypto.argon2-memory",
		64,
		"Memory parameter in megabytes for the Argon2id key derivation function.",
	)

	cmd.Flags().Uint8(
		"crypto.argon2-threads",
		4,
		"Number of threads for the Argon2id key derivation function.",
	)

	cmd.Flags().Uint32(
		"crypto.argon2-key-len",
		32,
		"Length in bytes of the derived key for the Argon2id function.",
	)
}

func runGenerate(cmd *cobra.Command, args []string) error {
	logger.Info("Starting key generation...")

	cfg, err := loadKeyGenConfig()
	if err != nil {
		return err
	}

	if err := validateKeyGenConfig(cfg); err != nil {
		return err
	}

	return generateKeys(cfg)
}

func loadKeyGenConfig() (KeyGenConfig, error) {
	var cfg KeyGenConfig

	if err := config.Unmarshal(&cfg); err != nil {
		return KeyGenConfig{}, fmt.Errorf("load key generation config: %w", err)
	}

	return cfg, nil
}

func validateKeyGenConfig(cfg KeyGenConfig) error {
	if cfg.PrivKeyOutputPath == "" {
		return fmt.Errorf("private key path is required")
	}

	if cfg.PubKeyOutputPath == "" {
		return fmt.Errorf("public key path is required")
	}

	if err := cfg.Crypto.ValidateForEncryption(); err != nil {
		return fmt.Errorf("invalid crypto config: %w", err)
	}

	return nil
}

func generateKeys(cfg KeyGenConfig) error {
	privKeyPath, pubKeyPath, err := resolveKeyPaths(cfg)
	if err != nil {
		return err
	}

	privateKey, publicKey, err := prepareKeyPair(privKeyPath, pubKeyPath, cfg.SkipPEMPresenceCheck)
	if err != nil {
		return err
	}

	if err := writeKeyPair(privateKey, publicKey, cfg.Crypto); err != nil {
		return err
	}

	logKeyGenerationSuccess(privKeyPath, pubKeyPath, publicKey)

	return nil
}

func resolveKeyPaths(cfg KeyGenConfig) (string, string, error) {
	privKeyPath, err := filepath.Abs(cfg.PrivKeyOutputPath)
	if err != nil {
		return "", "", fmt.Errorf("process private key path: %w", err)
	}

	pubKeyPath, err := filepath.Abs(cfg.PubKeyOutputPath)
	if err != nil {
		return "", "", fmt.Errorf("process public key path: %w", err)
	}

	return privKeyPath, pubKeyPath, nil
}

func prepareKeyPair(
	privKeyPath string,
	pubKeyPath string,
	skipPresenceCheck bool,
) (*internalkeys.PrivateKey, *internalkeys.PublicKey, error) {
	if !skipPresenceCheck {
		if err := internalkeys.CheckKeyPathsExistence(privKeyPath, pubKeyPath); err != nil {
			return nil, nil, fmt.Errorf("check key files existence: %w", err)
		}
	}

	privateKey, publicKey, err := internalkeys.GenerateKeyPair(privKeyPath, pubKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	return privateKey, publicKey, nil
}

func writeKeyPair(
	privateKey *internalkeys.PrivateKey,
	publicKey *internalkeys.PublicKey,
	cryptoCfg internalkeys.KeyEncryptionConfig,
) error {
	if err := privateKey.SealWithPassphrase(cryptoCfg); err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	if err := privateKey.SavePEMToFile(); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if err := publicKey.SavePEMToFile(); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

func logKeyGenerationSuccess(
	privKeyPath string,
	pubKeyPath string,
	publicKey *internalkeys.PublicKey,
) {
	logger.Info("Key generation successful!")
	logger.Info(fmt.Sprintf("Private key created at: %s", privKeyPath))
	logger.Info(fmt.Sprintf("Public key created at: %s", pubKeyPath))
	logger.Info(fmt.Sprintf("Public key fingerprint (SHA-256): %s", publicKey.FingerprintBase64()))
}
