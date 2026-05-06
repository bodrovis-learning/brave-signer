package hashers

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/sha3"
)

const DefaultHasherName = "sha3-256"

var ErrUnsupportedAlgorithm = errors.New("unsupported hash algorithm")

type Hasher struct {
	Name        string
	HashType    crypto.Hash
	Constructor func() hash.Hash
}

type hashDefinition struct {
	Constructor func() hash.Hash
	Hash        crypto.Hash
}

var hashFunctionMap = map[string]hashDefinition{
	"sha3-256": {sha3.New256, crypto.SHA3_256},
	"sha3-512": {sha3.New512, crypto.SHA3_512},
	"sha256":   {sha256.New, crypto.SHA256},
	"sha512":   {sha512.New, crypto.SHA512},
}

func New(algo string) (*Hasher, error) {
	algo = normalizeAlgorithm(algo)

	hf, ok := hashFunctionMap[algo]
	if !ok {
		return nil, fmt.Errorf(
			"%w %q; supported algorithms: %s",
			ErrUnsupportedAlgorithm,
			algo,
			strings.Join(SupportedAlgorithms(), ", "),
		)
	}

	return &Hasher{
		Name:        algo,
		HashType:    hf.Hash,
		Constructor: hf.Constructor,
	}, nil
}

func SupportedAlgorithms() []string {
	algorithms := make([]string, 0, len(hashFunctionMap))

	for algorithm := range hashFunctionMap {
		algorithms = append(algorithms, algorithm)
	}

	slices.Sort(algorithms)

	return algorithms
}

func normalizeAlgorithm(algo string) string {
	return strings.ToLower(strings.TrimSpace(algo))
}

func (h *Hasher) HashFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file %q: %w", filePath, err)
	}
	defer func() {
		_ = file.Close()
	}()

	hasher := h.Constructor()

	if _, err := io.Copy(hasher, file); err != nil {
		return nil, fmt.Errorf("hash file %q: %w", filePath, err)
	}

	return hasher.Sum(nil), nil
}
