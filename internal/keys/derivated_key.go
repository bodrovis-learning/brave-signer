package keys

import (
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const maxPassphraseLen = 1024

func DeriveKey(cryptoConfig KeyEncryptionConfig, salt []byte, passphrase []byte) ([]byte, error) {
	if err := cryptoConfig.ValidateKDF(); err != nil {
		return nil, fmt.Errorf("invalid crypto config: %w", err)
	}

	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	if len(passphrase) > maxPassphraseLen {
		return nil, fmt.Errorf("passphrase too long: got %d bytes, max %d", len(passphrase), maxPassphraseLen)
	}

	key := argon2.IDKey(
		passphrase,
		salt,
		cryptoConfig.Argon2Time,
		cryptoConfig.Argon2Memory*1024,
		cryptoConfig.Argon2Threads,
		cryptoConfig.Argon2KeyLen,
	)

	return key, nil
}

func DeriveKeyWithPassphrasePrompt(cryptoConfig KeyEncryptionConfig, salt []byte) ([]byte, error) {
	passphrase, err := ReadPassphrase("Enter passphrase: ")
	if err != nil {
		return nil, err
	}
	defer zeroBytes(passphrase)

	key, err := DeriveKey(cryptoConfig, salt, passphrase)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	return key, nil
}

func ReadPassphrase(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)

	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	if len(passphrase) > maxPassphraseLen {
		zeroBytes(passphrase)
		return nil, fmt.Errorf("passphrase too long: got %d bytes, max %d", len(passphrase), maxPassphraseLen)
	}

	return passphrase, nil
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
