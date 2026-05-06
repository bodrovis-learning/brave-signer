package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ResolveExistingFile converts a path to an absolute path and checks that it exists and is a file.
func ResolveExistingFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("file path is required")
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("convert path to absolute: %w", err)
	}

	pathInfo, err := pathInfo(absolutePath)
	if err != nil {
		return "", err
	}

	if pathInfo.IsDir() {
		return "", fmt.Errorf("path %q is a directory, not a file", absolutePath)
	}

	return absolutePath, nil
}

func pathInfo(path string) (fs.FileInfo, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("path %q does not exist", path)
		}

		return nil, fmt.Errorf("fetch file info for %q: %w", path, err)
	}

	return fileInfo, nil
}
