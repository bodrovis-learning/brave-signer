package keys

import "fmt"

type KeyEncryptionConfig struct {
	SaltSize      int    `mapstructure:"salt-size"`
	Argon2Time    uint32 `mapstructure:"argon2-time"`
	Argon2Memory  uint32 `mapstructure:"argon2-memory"`
	Argon2Threads uint8  `mapstructure:"argon2-threads"`
	Argon2KeyLen  uint32 `mapstructure:"argon2-key-len"`
}

func (cfg KeyEncryptionConfig) ValidateForEncryption() error {
	if cfg.SaltSize < 16 {
		return fmt.Errorf("salt size must be at least 16 bytes")
	}

	return cfg.ValidateKDF()
}

func (cfg KeyEncryptionConfig) ValidateKDF() error {
	if cfg.Argon2Time == 0 {
		return fmt.Errorf("argon2 time must be greater than 0")
	}

	if cfg.Argon2Memory == 0 {
		return fmt.Errorf("argon2 memory must be greater than 0")
	}

	if cfg.Argon2Threads == 0 {
		return fmt.Errorf("argon2 threads must be greater than 0")
	}

	if cfg.Argon2KeyLen != 32 {
		return fmt.Errorf("argon2 key length must be 32 bytes")
	}

	return nil
}
