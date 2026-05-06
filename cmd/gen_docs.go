package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func genDocsCmd(rootCmd *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:    "gendocs",
		Short:  "Generate markdown docs.",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateDocs(rootCmd, "./docs")
		},
	}
}

func generateDocs(rootCmd *cobra.Command, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create docs dir: %w", err)
	}

	if err := doc.GenMarkdownTree(rootCmd, dir); err != nil {
		return fmt.Errorf("generate markdown docs: %w", err)
	}

	return nil
}
