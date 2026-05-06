package keys

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	encryptedPrivateKeyPEMType = "ENCRYPTED ED25519 PRIVATE KEY"

	headerNonce   = "Nonce"
	headerSalt    = "Salt"
	headerKDF     = "Key-Derivation-Function"
	headerCipher  = "Cipher"
	headerTime    = "Argon2-Time"
	headerMemory  = "Argon2-Memory"
	headerThreads = "Argon2-Threads"
	headerKeyLen  = "Argon2-Key-Len"

	kdfArgon2ID             = "Argon2id"
	cipherXChaCha20Poly1305 = "XChaCha20-Poly1305"
)

// PrivateKey holds an Ed25519 private key and PEM-related metadata.
type PrivateKey struct {
	BaseKey
	Data    ed25519.PrivateKey
	PEMData *pem.Block
}

func NewPrivateKey(path string, raw ed25519.PrivateKey) *PrivateKey {
	return &PrivateKey{
		BaseKey: BaseKey{Path: path},
		Data:    raw,
	}
}

// SealWithPassphrase encrypts the private key using Argon2id + XChaCha20-Poly1305.
func (k *PrivateKey) SealWithPassphrase(cryptoConfig KeyEncryptionConfig) error {
	if k == nil {
		return fmt.Errorf("private key is nil")
	}

	if len(k.Data) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key size: got %d bytes, want %d", len(k.Data), ed25519.PrivateKeySize)
	}

	if err := cryptoConfig.ValidateForEncryption(); err != nil {
		return fmt.Errorf("invalid crypto config: %w", err)
	}

	salt, err := generateSalt(cryptoConfig.SaltSize)
	if err != nil {
		return err
	}

	derivedKey, err := DeriveKeyWithPassphrasePrompt(cryptoConfig, salt)
	if err != nil {
		return fmt.Errorf("derive encryption key: %w", err)
	}
	defer zeroize(derivedKey)

	crypter, err := generateCrypter(derivedKey)
	if err != nil {
		return err
	}

	nonce, err := generateNonce(crypter)
	if err != nil {
		return err
	}

	encrypted := crypter.Seal(nil, nonce, k.Data, nil)

	zeroize(k.Data)
	k.Data = nil

	k.PEMData = &pem.Block{
		Type:  encryptedPrivateKeyPEMType,
		Bytes: encrypted,
		Headers: map[string]string{
			headerNonce:   base64.StdEncoding.EncodeToString(nonce),
			headerSalt:    base64.StdEncoding.EncodeToString(salt),
			headerKDF:     kdfArgon2ID,
			headerCipher:  cipherXChaCha20Poly1305,
			headerTime:    strconv.FormatUint(uint64(cryptoConfig.Argon2Time), 10),
			headerMemory:  strconv.FormatUint(uint64(cryptoConfig.Argon2Memory), 10),
			headerThreads: strconv.FormatUint(uint64(cryptoConfig.Argon2Threads), 10),
			headerKeyLen:  strconv.FormatUint(uint64(cryptoConfig.Argon2KeyLen), 10),
		},
	}

	return nil
}

func (k *PrivateKey) SavePEMToFile() error {
	if k == nil {
		return fmt.Errorf("private key is nil")
	}

	if k.PEMData == nil {
		return fmt.Errorf("cannot save private key: no PEM data present; seal the key first")
	}

	file, err := os.OpenFile(k.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create private key file %q: %w", k.Path, err)
	}
	defer func() {
		_ = file.Close()
	}()

	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("set private key file permissions: %w", err)
	}

	if err := pem.Encode(file, k.PEMData); err != nil {
		return fmt.Errorf("encode private key PEM: %w", err)
	}

	return nil
}

func (k *PrivateKey) SignMessage(message []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	if len(k.Data) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d bytes, want %d", len(k.Data), ed25519.PrivateKeySize)
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	return ed25519.Sign(k.Data, message), nil
}

func LoadPrivateFromPEMFile(path string) (*PrivateKey, error) {
	block, err := decodePEMFile(path)
	if err != nil {
		return nil, err
	}

	cryptoConfig, nonce, salt, err := parsePrivateKeyPEMHeaders(block)
	if err != nil {
		return nil, err
	}

	key, err := DeriveKeyWithPassphrasePrompt(cryptoConfig, salt)
	if err != nil {
		return nil, fmt.Errorf("derive decryption key: %w", err)
	}
	defer zeroize(key)

	crypter, err := generateCrypter(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != crypter.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: got %d bytes, want %d", len(nonce), crypter.NonceSize())
	}

	plaintext, err := crypter.Open(nil, nonce, block.Bytes, nil)
	if err != nil {
		return nil, fmt.Errorf("private key decryption failed: wrong passphrase, corrupted key file, or invalid encryption metadata")
	}

	privateKey := ed25519.PrivateKey(plaintext)
	if len(privateKey) != ed25519.PrivateKeySize {
		zeroize(plaintext)
		return nil, fmt.Errorf("invalid private key size: got %d bytes, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	return &PrivateKey{
		BaseKey: BaseKey{Path: path},
		Data:    privateKey,
		PEMData: block,
	}, nil
}

func parsePrivateKeyPEMHeaders(block *pem.Block) (KeyEncryptionConfig, []byte, []byte, error) {
	if block == nil {
		return KeyEncryptionConfig{}, nil, nil, fmt.Errorf("PEM block is nil")
	}

	if block.Type != encryptedPrivateKeyPEMType {
		return KeyEncryptionConfig{}, nil, nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}

	if block.Headers[headerKDF] != kdfArgon2ID {
		return KeyEncryptionConfig{}, nil, nil, fmt.Errorf("unsupported key derivation function %q", block.Headers[headerKDF])
	}

	if block.Headers[headerCipher] != cipherXChaCha20Poly1305 {
		return KeyEncryptionConfig{}, nil, nil, fmt.Errorf("unsupported cipher %q", block.Headers[headerCipher])
	}

	nonce, err := decodeBase64Header(block, headerNonce)
	if err != nil {
		return KeyEncryptionConfig{}, nil, nil, err
	}

	salt, err := decodeBase64Header(block, headerSalt)
	if err != nil {
		return KeyEncryptionConfig{}, nil, nil, err
	}

	cfg := KeyEncryptionConfig{
		Argon2Time:    uint32Header(block, headerTime),
		Argon2Memory:  uint32Header(block, headerMemory),
		Argon2Threads: uint8Header(block, headerThreads),
		Argon2KeyLen:  uint32Header(block, headerKeyLen),
		SaltSize:      len(salt),
	}

	if err := cfg.ValidateKDF(); err != nil {
		return KeyEncryptionConfig{}, nil, nil, fmt.Errorf("invalid KDF config in PEM headers: %w", err)
	}

	return cfg, nonce, salt, nil
}

func decodeBase64Header(block *pem.Block, name string) ([]byte, error) {
	value, ok := block.Headers[name]
	if !ok {
		return nil, fmt.Errorf("missing PEM header %q", name)
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode PEM header %q: %w", name, err)
	}

	return decoded, nil
}

func uint32Header(block *pem.Block, name string) uint32 {
	value, _ := strconv.ParseUint(block.Headers[name], 10, 32)
	return uint32(value)
}

func uint8Header(block *pem.Block, name string) uint8 {
	value, _ := strconv.ParseUint(block.Headers[name], 10, 8)
	return uint8(value)
}

func decodePEMFile(path string) (*pem.Block, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PEM file %q: %w", path, err)
	}

	block, rest := pem.Decode(fileBytes)
	if block == nil {
		return nil, errors.New("decode PEM block containing the key")
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("decode PEM file: extra data encountered after PEM block")
	}

	return block, nil
}

func generateSalt(saltSize int) ([]byte, error) {
	if saltSize <= 0 {
		return nil, fmt.Errorf("salt size must be greater than 0")
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	return salt, nil
}

func generateNonce(crypter cipher.AEAD) ([]byte, error) {
	if crypter == nil {
		return nil, fmt.Errorf("crypter is nil")
	}

	nonce := make([]byte, crypter.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	return nonce, nil
}

func generateCrypter(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create XChaCha20-Poly1305 cipher: %w", err)
	}

	return aead, nil
}

func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	return io.ReadFull(os.Stdin, p)
}
