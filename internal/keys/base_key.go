package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
)

// BaseKey holds the shared attributes for key files.
type BaseKey struct {
	Path string
}

func GenerateKeyPair(privPath, pubPath string) (*PrivateKey, *PublicKey, error) {
	if privPath == "" {
		return nil, nil, fmt.Errorf("private key path is required")
	}

	if pubPath == "" {
		return nil, nil, fmt.Errorf("public key path is required")
	}

	pubData, privData, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 key pair: %w", err)
	}

	return NewPrivateKey(privPath, privData), NewPublicKey(pubPath, pubData), nil
}

func CheckKeyPathsExistence(privPath, pubPath string) error {
	if err := ensureDoesNotExist("private key", privPath); err != nil {
		return err
	}

	if err := ensureDoesNotExist("public key", pubPath); err != nil {
		return err
	}

	return nil
}

func ensureDoesNotExist(label string, path string) error {
	if path == "" {
		return fmt.Errorf("%s path is required", label)
	}

	exists, err := fileExists(path)
	if err != nil {
		return fmt.Errorf("check %s path %q: %w", label, path, err)
	}

	if exists {
		return fmt.Errorf(
			"%s already exists at %q; use --skip-pem-presence-check to overwrite",
			label,
			path,
		)
	}

	return nil
}

func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, fmt.Errorf("stat path %q: %w", path, err)
	}

	return !info.IsDir(), nil
}
