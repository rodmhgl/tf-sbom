package sbom

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HasTerraformFiles checks if a directory contains any .tf files
func HasTerraformFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tf") {
			return true
		}
	}
	return false
}

// ValidateTerraformDirectory checks if a directory exists and is suitable for Terraform module loading
func ValidateTerraformDirectory(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path must be a directory containing Terraform files: %s", path)
	}

	return nil
}

// FindTerraformModules recursively searches for directories containing Terraform files
func FindTerraformModules(root string, recursive bool) ([]string, error) {
	if !recursive {
		// Non-recursive mode: return the root directory if it has .tf files, otherwise return an empty slice
		if HasTerraformFiles(root) {
			return []string{root}, nil
		}
		return []string{}, nil // Return an empty slice if no .tf files are found
	}

	var modules []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Log the error and continue walking instead of aborting
			fmt.Fprintf(os.Stderr, "Warning: skipping %s due to error: %v\n", path, err)
			return nil
		}

		// Skip hidden directories (e.g., .terraform, .git)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != root {
			return filepath.SkipDir
		}

		if d.IsDir() && HasTerraformFiles(path) {
			modules = append(modules, path)
		}
		return nil
	})
	return modules, err
}
