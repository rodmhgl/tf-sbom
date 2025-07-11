package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateTerraformDirectory(t *testing.T) {
	// Test with existing directory
	t.Run("existing directory", func(t *testing.T) {
		// Create a temporary directory
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		err = ValidateTerraformDirectory(tmpDir)
		if err != nil {
			t.Errorf("ValidateTerraformDirectory() = %v, want nil", err)
		}
	})

	// Test with non-existing path
	t.Run("non-existing path", func(t *testing.T) {
		err := ValidateTerraformDirectory("/path/that/does/not/exist")
		if err == nil {
			t.Error("ValidateTerraformDirectory() = nil, want error")
		}
		if !strings.Contains(err.Error(), "path does not exist") {
			t.Errorf("error message = %v, want 'path does not exist'", err.Error())
		}
	})

	// Test with file instead of directory
	t.Run("file instead of directory", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "test_*.tf")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		err = ValidateTerraformDirectory(tmpFile.Name())
		if err == nil {
			t.Error("ValidateTerraformDirectory() = nil, want error for file")
		}
		if !strings.Contains(err.Error(), "path must be a directory containing Terraform files") {
			t.Errorf("error message = %v, want 'path must be a directory containing Terraform files'", err.Error())
		}
	})
}

func TestHasTerraformFiles(t *testing.T) {
	// Test with directory containing .tf files
	t.Run("directory with tf files", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_has_tf_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create .tf file
		err = os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# test"), 0644)
		if err != nil {
			t.Fatalf("failed to create .tf file: %v", err)
		}

		if !HasTerraformFiles(tmpDir) {
			t.Error("HasTerraformFiles() = false, want true for directory with .tf files")
		}
	})

	// Test with directory containing only non-.tf files
	t.Run("directory without tf files", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_no_tf_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create non-.tf files
		err = os.WriteFile(filepath.Join(tmpDir, "README.md"), []byte("# test"), 0644)
		if err != nil {
			t.Fatalf("failed to create README file: %v", err)
		}

		err = os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte("{}"), 0644)
		if err != nil {
			t.Fatalf("failed to create JSON file: %v", err)
		}

		if HasTerraformFiles(tmpDir) {
			t.Error("HasTerraformFiles() = true, want false for directory without .tf files")
		}
	})

	// Test with empty directory
	t.Run("empty directory", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_empty_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		if HasTerraformFiles(tmpDir) {
			t.Error("HasTerraformFiles() = true, want false for empty directory")
		}
	})

	// Test with non-existent directory
	t.Run("non-existent directory", func(t *testing.T) {
		if HasTerraformFiles("/path/that/does/not/exist") {
			t.Error("HasTerraformFiles() = true, want false for non-existent directory")
		}
	})

	// Test with unreadable directory
	t.Run("unreadable directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping permission test when running as root")
		}

		tmpDir, err := os.MkdirTemp("", "test_unreadable_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create .tf file first
		err = os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# test"), 0644)
		if err != nil {
			t.Fatalf("failed to create .tf file: %v", err)
		}

		// Make directory unreadable
		err = os.Chmod(tmpDir, 0000)
		if err != nil {
			t.Fatalf("failed to change directory permissions: %v", err)
		}
		defer os.Chmod(tmpDir, 0755) // Restore permissions for cleanup

		if HasTerraformFiles(tmpDir) {
			t.Error("HasTerraformFiles() = true, want false for unreadable directory")
		}
	})

	// Test with directory containing subdirectories
	t.Run("directory with subdirectories", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_subdirs_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create subdirectory
		subDir := filepath.Join(tmpDir, "subdir")
		err = os.MkdirAll(subDir, 0755)
		if err != nil {
			t.Fatalf("failed to create subdirectory: %v", err)
		}

		// Create .tf file in subdirectory (should not count)
		err = os.WriteFile(filepath.Join(subDir, "main.tf"), []byte("# test"), 0644)
		if err != nil {
			t.Fatalf("failed to create .tf file in subdirectory: %v", err)
		}

		if HasTerraformFiles(tmpDir) {
			t.Error("HasTerraformFiles() = true, want false for directory with .tf files only in subdirectories")
		}
	})
}
