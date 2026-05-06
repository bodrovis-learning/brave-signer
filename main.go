package main

import (
	"fmt"

	"brave_signer/cmd"
	"brave_signer/internal/logger"
)

func main() {
	if err := run(); err != nil {
		logger.HaltOnErr(err, "command failed")
	}
}

func run() error {
	rootCmd := cmd.RootCmd()

	if err := rootCmd.Execute(); err != nil {
		return fmt.Errorf("execute root command: %w", err)
	}

	return nil
}
