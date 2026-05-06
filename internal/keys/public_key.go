package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

const publicKeyPEMType = "ED25519 PUBLIC KEY"

// PublicKey holds an Ed25519 public key.
type PublicKey struct {
	BaseKey
	Data ed25519.PublicKey
}

func NewPublicKey(path string, raw ed25519.PublicKey) *PublicKey {
	return &PublicKey{
		BaseKey: BaseKey{Path: path},
		Data:    raw,
	}
}

// PEMBlock returns the public key in PEM block form.
func (k *PublicKey) PEMBlock() (*pem.Block, error) {
	if k == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	if len(k.Data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d bytes, want %d", len(k.Data), ed25519.PublicKeySize)
	}

	return &pem.Block{
		Type:  publicKeyPEMType,
		Bytes: k.Data,
	}, nil
}

func (k *PublicKey) SavePEMToFile() error {
	if k == nil {
		return fmt.Errorf("public key is nil")
	}

	block, err := k.PEMBlock()
	if err != nil {
		return err
	}

	file, err := os.OpenFile(k.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create public key file %q: %w", k.Path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("write public key PEM: %w", err)
	}

	return nil
}

func (k *PublicKey) VerifySignature(digest, rawSignature []byte) bool {
	if k == nil {
		return false
	}

	if len(k.Data) != ed25519.PublicKeySize {
		return false
	}

	if len(rawSignature) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(k.Data, digest, rawSignature)
}

func (k *PublicKey) FingerprintBase64() string {
	if k == nil || len(k.Data) == 0 {
		return ""
	}

	hash := sha256.Sum256(k.Data)

	return base64.StdEncoding.EncodeToString(hash[:])
}

func LoadPublicFromPEMFile(path string) (*PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file %q: %w", path, err)
	}

	block, rest := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("public key file %q does not contain a valid PEM block", path)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("public key file %q contains extra data after the first PEM block", path)
	}

	if block.Type != publicKeyPEMType {
		return nil, fmt.Errorf("unexpected public key PEM type %q, want %q", block.Type, publicKeyPEMType)
	}

	publicKey := ed25519.PublicKey(block.Bytes)
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d bytes, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	return NewPublicKey(path, publicKey), nil
}
