package main

import (
	"fmt"
	"os"
	"os/exec"
)

func runCommand(name string, args ...string) error {
	fmt.Printf("Running %s %v...\n", name, args)

	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w", name, args, err)
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	commands := []struct {
		name string
		args []string
	}{
		{"gofumpt", []string{"-w", "."}},
		{"go", []string{"fmt", "./..."}},
		{"go", []string{"vet", "./..."}},
		{"golangci-lint", []string{"run", "./..."}},
		{"staticcheck", []string{"./..."}},
	}

	for _, command := range commands {
		if err := runCommand(command.name, command.args...); err != nil {
			return err
		}
	}

	fmt.Println("All checks completed!")
	return nil
}
