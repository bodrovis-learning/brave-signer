package signatures

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	"brave-signer/internal/keys"
)

const signerInfoLengthSize = 4

type Signature struct {
	Data    []byte
	Package []byte
}

var (
	ErrSignatureMismatch = errors.New("signature mismatch")
	ErrMalformedPackage  = errors.New("malformed signature package")
)

func New(data []byte) (*Signature, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("signature data is empty")
	}

	if len(data) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature size: got %d bytes, want %d", len(data), ed25519.SignatureSize)
	}

	return &Signature{
		Data: data,
	}, nil
}

func (s *Signature) GeneratePackage(signerInfo string) (*Signature, error) {
	if s == nil {
		return nil, fmt.Errorf("signature is nil")
	}

	if len(s.Data) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature size: got %d bytes, want %d", len(s.Data), ed25519.SignatureSize)
	}

	signerInfoBytes := []byte(signerInfo)
	if len(signerInfoBytes) > math.MaxUint32 {
		return nil, fmt.Errorf("signer info is too large")
	}

	var buf bytes.Buffer
	buf.Grow(signerInfoLengthSize + len(signerInfoBytes) + len(s.Data))

	if err := binary.Write(&buf, binary.BigEndian, uint32(len(signerInfoBytes))); err != nil {
		return nil, fmt.Errorf("write signer info length: %w", err)
	}

	if _, err := buf.Write(signerInfoBytes); err != nil {
		return nil, fmt.Errorf("write signer info: %w", err)
	}

	if _, err := buf.Write(s.Data); err != nil {
		return nil, fmt.Errorf("write signature: %w", err)
	}

	s.Package = buf.Bytes()

	return s, nil
}

func (s *Signature) SaveToSIGFile(initialFilePath string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("signature is nil")
	}

	if len(s.Package) == 0 {
		return "", fmt.Errorf("signature package is empty")
	}

	sigFilePath := signatureFilePath(initialFilePath)

	if err := os.WriteFile(sigFilePath, s.Package, 0o644); err != nil {
		return "", fmt.Errorf("write signature file %q: %w", sigFilePath, err)
	}

	return sigFilePath, nil
}

func (s *Signature) VerifyDigest(digest []byte, publicKey *keys.PublicKey) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("signature is nil")
	}

	if len(digest) == 0 {
		return nil, fmt.Errorf("digest is empty")
	}

	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	signerInfo, signatureBytes, err := parsePackage(s.Data)
	if err != nil {
		return nil, err
	}

	if !publicKey.VerifySignature(digest, signatureBytes) {
		return nil, ErrSignatureMismatch
	}

	return signerInfo, nil
}

func LoadRawFromSIGFile(initialFilePath string) (*Signature, error) {
	sigFilePath := signatureFilePath(initialFilePath)

	data, err := os.ReadFile(sigFilePath)
	if err != nil {
		return nil, fmt.Errorf("read signature file %q: %w", sigFilePath, err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("%w: signature file is empty", ErrMalformedPackage)
	}

	return &Signature{
		Data: data,
	}, nil
}

func parsePackage(data []byte) ([]byte, []byte, error) {
	if len(data) < signerInfoLengthSize+ed25519.SignatureSize {
		return nil, nil, fmt.Errorf(
			"%w: package too small: got %d bytes",
			ErrMalformedPackage,
			len(data),
		)
	}

	buf := bytes.NewReader(data)

	var signerInfoLength uint32
	if err := binary.Read(buf, binary.BigEndian, &signerInfoLength); err != nil {
		return nil, nil, fmt.Errorf("read signer info length: %w", err)
	}

	if uint64(signerInfoLength) > uint64(buf.Len()-ed25519.SignatureSize) {
		return nil, nil, fmt.Errorf(
			"%w: signer info length %d exceeds package payload",
			ErrMalformedPackage,
			signerInfoLength,
		)
	}

	signerInfo := make([]byte, signerInfoLength)
	if _, err := io.ReadFull(buf, signerInfo); err != nil {
		return nil, nil, fmt.Errorf("read signer info: %w", err)
	}

	signatureBytes, err := io.ReadAll(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("read signature: %w", err)
	}

	if len(signatureBytes) != ed25519.SignatureSize {
		return nil, nil, fmt.Errorf(
			"%w: invalid signature size: got %d bytes, want %d",
			ErrMalformedPackage,
			len(signatureBytes),
			ed25519.SignatureSize,
		)
	}

	return signerInfo, signatureBytes, nil
}

func signatureFilePath(initialFilePath string) string {
	return filepath.Join(filepath.Dir(initialFilePath), filepath.Base(initialFilePath)+".sig")
}
