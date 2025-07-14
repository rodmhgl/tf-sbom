package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSBOM(t *testing.T) {
	// Test with non-existing directory
	t.Run("non-existing directory", func(t *testing.T) {
		_, err := Generate("/path/that/does/not/exist", false)
		if err == nil {
			t.Error("Generate() = nil, want error")
		}
	})

	// Test with valid but empty directory (non-recursive)
	t.Run("empty directory non-recursive", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		result, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 0 {
			t.Errorf("len(result.Modules) = %v, want 0", len(result.Modules))
		}

		// Verify SBOM structure is still valid
		if result.Version != "1.0" {
			t.Errorf("result.Version = %v, want '1.0'", result.Version)
		}
		if result.Tool != "terraform-sbom" {
			t.Errorf("result.Tool = %v, want 'terraform-sbom'", result.Tool)
		}
		if result.Generated == "" {
			t.Error("result.Generated should not be empty")
		}
	})

	// Test with valid but empty directory (recursive)
	t.Run("empty directory recursive", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_recursive_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create some empty subdirectories to ensure recursive scan doesn't find anything
		emptySubDirs := []string{"subdir1", "subdir2", "deep/nested/empty"}
		for _, subDir := range emptySubDirs {
			err = os.MkdirAll(filepath.Join(tmpDir, subDir), 0755)
			if err != nil {
				t.Fatalf("failed to create empty subdirectory %s: %v", subDir, err)
			}
		}

		result, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 0 {
			t.Errorf("len(result.Modules) = %v, want 0", len(result.Modules))
		}

		// Verify SBOM structure is still valid
		if result.Version != "1.0" {
			t.Errorf("result.Version = %v, want '1.0'", result.Version)
		}
		if result.Tool != "terraform-sbom" {
			t.Errorf("result.Tool = %v, want 'terraform-sbom'", result.Tool)
		}
		if result.Generated == "" {
			t.Error("result.Generated should not be empty")
		}
	})

	// Test empty directory with non-tf files (both recursive modes)
	t.Run("directory with non-tf files", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_non_tf_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create various non-terraform files
		nonTfFiles := map[string]string{
			"README.md":    "# Project Documentation",
			"package.json": `{"name": "test"}`,
			"Dockerfile":   "FROM alpine:latest",
			"config.yaml":  "key: value",
			"script.sh":    "#!/bin/bash\necho hello",
		}

		for filename, content := range nonTfFiles {
			err = os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
			if err != nil {
				t.Fatalf("failed to create file %s: %v", filename, err)
			}
		}

		// Create subdirectory with non-tf files
		subDir := filepath.Join(tmpDir, "subdir")
		err = os.MkdirAll(subDir, 0755)
		if err != nil {
			t.Fatalf("failed to create subdirectory: %v", err)
		}

		err = os.WriteFile(filepath.Join(subDir, "notes.txt"), []byte("Some notes"), 0644)
		if err != nil {
			t.Fatalf("failed to create file in subdirectory: %v", err)
		}

		// Test non-recursive
		sbomNonRecursive, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate(recursive=false) = %v, want nil", err)
		}
		if len(sbomNonRecursive.Modules) != 0 {
			t.Errorf("non-recursive len(result.Modules) = %v, want 0", len(sbomNonRecursive.Modules))
		}

		// Test recursive
		sbomRecursive, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate(recursive=true) = %v, want nil", err)
		}
		if len(sbomRecursive.Modules) != 0 {
			t.Errorf("recursive len(result.Modules) = %v, want 0", len(sbomRecursive.Modules))
		}

		// Both should produce identical results for directories without .tf files
		if sbomNonRecursive.Version != sbomRecursive.Version {
			t.Error("SBOM versions should be identical for non-recursive vs recursive on empty directories")
		}
	})

	// Test with directory containing Terraform configuration
	t.Run("directory with terraform config", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create a simple Terraform configuration
		tfConfig := `
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  
  name = "test-vpc"
  cidr = "10.0.0.0/16"
}

module "security_group" {
  source = "terraform-aws-modules/security-group/aws"
  
  name        = "test-sg"
  description = "Test security group"
  vpc_id      = module.vpc.vpc_id
}
`
		configPath := filepath.Join(tmpDir, "main.tf")
		err = os.WriteFile(configPath, []byte(tfConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		result, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 2 {
			t.Errorf("len(result.Modules) = %v, want 2", len(result.Modules))
		}

		// Verify module details
		moduleNames := make(map[string]bool)
		for _, module := range result.Modules {
			moduleNames[module.Name] = true
			if module.Source == "" {
				t.Errorf("Module %s has empty source", module.Name)
			}
		}

		if !moduleNames["vpc"] {
			t.Error("Expected vpc module not found")
		}
		if !moduleNames["security_group"] {
			t.Error("Expected security_group module not found")
		}
	})

	// Test with invalid Terraform configuration
	t.Run("invalid terraform configuration", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create malformed Terraform configuration
		invalidConfig := `
module "broken" {
  source = "invalid-source"
  # Missing closing brace and invalid syntax
  invalid_attribute = [
`
		configPath := filepath.Join(tmpDir, "main.tf")
		err = os.WriteFile(configPath, []byte(invalidConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		_, err = Generate(tmpDir, false)
		if err == nil {
			t.Error("Generate() = nil, want error for invalid configuration")
		}
	})

	// Test with different module source types
	t.Run("different module source types", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create configuration with various module sources
		tfConfig := `
module "local_module" {
  source = "./modules/local"
}

module "git_module" {
  source = "git::https://github.com/example/terraform-module.git"
  version = "v1.0.0"
}

module "registry_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}

module "no_version_module" {
  source = "github.com/example/module"
}
`
		configPath := filepath.Join(tmpDir, "main.tf")
		err = os.WriteFile(configPath, []byte(tfConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		result, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 4 {
			t.Errorf("len(result.Modules) = %v, want 4", len(result.Modules))
		}

		// Verify each module type
		modulesByName := make(map[string]ModuleInfo)
		for _, module := range result.Modules {
			modulesByName[module.Name] = module
		}

		// Check local module
		if localMod, exists := modulesByName["local_module"]; exists {
			if localMod.Source != "./modules/local" {
				t.Errorf("local_module.Source = %v, want ./modules/local", localMod.Source)
			}
			if localMod.Version != "" {
				t.Errorf("local_module.Version = %v, want empty", localMod.Version)
			}
		} else {
			t.Error("local_module not found")
		}

		// Check git module
		if gitMod, exists := modulesByName["git_module"]; exists {
			if gitMod.Source != "git::https://github.com/example/terraform-module.git" {
				t.Errorf("git_module.Source = %v, want git::https://github.com/example/terraform-module.git", gitMod.Source)
			}
			if gitMod.Version != "v1.0.0" {
				t.Errorf("git_module.Version = %v, want v1.0.0", gitMod.Version)
			}
		} else {
			t.Error("git_module not found")
		}

		// Check registry module
		if regMod, exists := modulesByName["registry_module"]; exists {
			if regMod.Source != "terraform-aws-modules/vpc/aws" {
				t.Errorf("registry_module.Source = %v, want terraform-aws-modules/vpc/aws", regMod.Source)
			}
			if regMod.Version != "~> 5.0" {
				t.Errorf("registry_module.Version = %v, want ~> 5.0", regMod.Version)
			}
		} else {
			t.Error("registry_module not found")
		}

		// Check module without version
		if noVerMod, exists := modulesByName["no_version_module"]; exists {
			if noVerMod.Source != "github.com/example/module" {
				t.Errorf("no_version_module.Source = %v, want github.com/example/module", noVerMod.Source)
			}
			if noVerMod.Version != "" {
				t.Errorf("no_version_module.Version = %v, want empty", noVerMod.Version)
			}
		} else {
			t.Error("no_version_module not found")
		}
	})

	// Test with edge cases
	t.Run("edge cases", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create configuration with edge cases
		tfConfig := `
module "special-chars_123" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}

module "long_module_name_with_many_underscores_and_dashes" {
  source = "./very/long/path/to/module/with/many/nested/directories"
}
`
		configPath := filepath.Join(tmpDir, "main.tf")
		err = os.WriteFile(configPath, []byte(tfConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write config file: %v", err)
		}

		result, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 2 {
			t.Errorf("len(result.Modules) = %v, want 2", len(result.Modules))
		}

		// Verify modules with special characters and long names
		moduleNames := make(map[string]bool)
		for _, module := range result.Modules {
			moduleNames[module.Name] = true
			// Ensure all modules have valid configuration information
			if module.Location == "" {
				t.Errorf("Module %s has empty location", module.Name)
			}
			if module.Filename == "" {
				t.Errorf("Module %s has empty filename", module.Name)
			}
		}

		if !moduleNames["special-chars_123"] {
			t.Error("Expected special-chars_123 module not found")
		}
		if !moduleNames["long_module_name_with_many_underscores_and_dashes"] {
			t.Error("Expected long_module_name_with_many_underscores_and_dashes module not found")
		}
	})

	// Test recursive=true with nested modules
	t.Run("recursive scan with nested modules", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_recursive_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create nested directory structure with Terraform files
		// Root level
		rootConfig := `
module "root_vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
`
		err = os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(rootConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write root config: %v", err)
		}

		// First level subdirectory
		subDir1 := filepath.Join(tmpDir, "environments", "prod")
		err = os.MkdirAll(subDir1, 0755)
		if err != nil {
			t.Fatalf("failed to create subdirectory: %v", err)
		}

		prodConfig := `
module "prod_database" {
  source = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"
}

module "prod_cache" {
  source = "./../../modules/redis"
}
`
		err = os.WriteFile(filepath.Join(subDir1, "main.tf"), []byte(prodConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write prod config: %v", err)
		}

		// Second level subdirectory
		subDir2 := filepath.Join(tmpDir, "modules", "app")
		err = os.MkdirAll(subDir2, 0755)
		if err != nil {
			t.Fatalf("failed to create app module directory: %v", err)
		}

		appConfig := `
module "app_alb" {
  source = "terraform-aws-modules/alb/aws"
  version = "v8.7.0"
}

module "app_ecs" {
  source = "git::https://github.com/example/ecs-module.git"
  version = "v1.2.3"
}
`
		err = os.WriteFile(filepath.Join(subDir2, "main.tf"), []byte(appConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write app config: %v", err)
		}

		// Empty directory (should be ignored)
		emptyDir := filepath.Join(tmpDir, "empty")
		err = os.MkdirAll(emptyDir, 0755)
		if err != nil {
			t.Fatalf("failed to create empty directory: %v", err)
		}

		// Directory with non-terraform files (should be ignored)
		nonTfDir := filepath.Join(tmpDir, "docs")
		err = os.MkdirAll(nonTfDir, 0755)
		if err != nil {
			t.Fatalf("failed to create docs directory: %v", err)
		}
		err = os.WriteFile(filepath.Join(nonTfDir, "README.md"), []byte("# Documentation"), 0644)
		if err != nil {
			t.Fatalf("failed to write README: %v", err)
		}

		// Test recursive scan
		result, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		// Should find modules from all directories with .tf files
		expectedModules := 5 // root_vpc, prod_database, prod_cache, app_alb, app_ecs
		if len(result.Modules) != expectedModules {
			t.Errorf("len(result.Modules) = %v, want %v", len(result.Modules), expectedModules)
		}

		// Verify specific modules are found
		moduleNames := make(map[string]bool)
		for _, module := range result.Modules {
			moduleNames[module.Name] = true
		}

		expectedNames := []string{"root_vpc", "prod_database", "prod_cache", "app_alb", "app_ecs"}
		for _, name := range expectedNames {
			if !moduleNames[name] {
				t.Errorf("Expected module %s not found", name)
			}
		}
	})

	// Test recursive=false vs recursive=true comparison
	t.Run("recursive vs non-recursive comparison", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_comparison_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Root level config
		rootConfig := `
module "root_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
`
		err = os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(rootConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write root config: %v", err)
		}

		// Nested config
		nestedDir := filepath.Join(tmpDir, "nested")
		err = os.MkdirAll(nestedDir, 0755)
		if err != nil {
			t.Fatalf("failed to create nested directory: %v", err)
		}

		nestedConfig := `
module "nested_module" {
  source = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"
}
`
		err = os.WriteFile(filepath.Join(nestedDir, "main.tf"), []byte(nestedConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write nested config: %v", err)
		}

		// Test non-recursive (should only find root module)
		sbomNonRecursive, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate(recursive=false) = %v, want nil", err)
		}

		if len(sbomNonRecursive.Modules) != 1 {
			t.Errorf("non-recursive len(result.Modules) = %v, want 1", len(sbomNonRecursive.Modules))
		}

		if sbomNonRecursive.Modules[0].Name != "root_module" {
			t.Errorf("non-recursive module name = %v, want 'root_module'", sbomNonRecursive.Modules[0].Name)
		}

		// Test recursive (should find both modules)
		sbomRecursive, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate(recursive=true) = %v, want nil", err)
		}

		if len(sbomRecursive.Modules) != 2 {
			t.Errorf("recursive len(result.Modules) = %v, want 2", len(sbomRecursive.Modules))
		}

		// Verify both modules are found
		moduleNames := make(map[string]bool)
		for _, module := range sbomRecursive.Modules {
			moduleNames[module.Name] = true
		}

		if !moduleNames["root_module"] {
			t.Error("recursive scan should find root_module")
		}
		if !moduleNames["nested_module"] {
			t.Error("recursive scan should find nested_module")
		}
	})

	// Test recursive with deeply nested structure
	t.Run("recursive scan with deep nesting", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_deep_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create deeply nested structure: a/b/c/d/e
		deepDir := filepath.Join(tmpDir, "a", "b", "c", "d", "e")
		err = os.MkdirAll(deepDir, 0755)
		if err != nil {
			t.Fatalf("failed to create deep directory: %v", err)
		}

		// Add terraform file at the deepest level
		deepConfig := `
module "deep_module" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"
}
`
		err = os.WriteFile(filepath.Join(deepDir, "main.tf"), []byte(deepConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write deep config: %v", err)
		}

		// Also add a config at an intermediate level
		midDir := filepath.Join(tmpDir, "a", "b")
		midConfig := `
module "mid_module" {
  source = "./local/path"
}
`
		err = os.WriteFile(filepath.Join(midDir, "variables.tf"), []byte(midConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write mid config: %v", err)
		}

		// Test recursive scan finds both
		result, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 2 {
			t.Errorf("len(result.Modules) = %v, want 2", len(result.Modules))
		}

		moduleNames := make(map[string]bool)
		for _, module := range result.Modules {
			moduleNames[module.Name] = true
		}

		if !moduleNames["deep_module"] {
			t.Error("Expected deep_module not found")
		}
		if !moduleNames["mid_module"] {
			t.Error("Expected mid_module not found")
		}
	})

	// Test with file instead of directory (should fail with clear error)
	t.Run("file instead of directory", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "test_*.tf")
		if err != nil {
			t.Fatalf("failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		// Write some terraform content to make it a valid .tf file
		_, err = tmpFile.WriteString(`
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
`)
		if err != nil {
			t.Fatalf("failed to write to temp file: %v", err)
		}

		_, err = Generate(tmpFile.Name(), false)
		if err == nil {
			t.Error("Generate() = nil, want error for file instead of directory")
		}
		if !strings.Contains(err.Error(), "path must be a directory containing Terraform files") {
			t.Errorf("error message = %v, want 'path must be a directory containing Terraform files'", err.Error())
		}
	})

	// Test recursive scan with unreadable directories
	t.Run("recursive scan with unreadable directory", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Skipping permission test when running as root")
		}

		tmpDir, err := os.MkdirTemp("", "test_terraform_unreadable_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create a readable directory with terraform config
		readableDir := filepath.Join(tmpDir, "readable")
		err = os.MkdirAll(readableDir, 0755)
		if err != nil {
			t.Fatalf("failed to create readable directory: %v", err)
		}

		readableConfig := `
module "readable_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
`
		err = os.WriteFile(filepath.Join(readableDir, "main.tf"), []byte(readableConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write readable config: %v", err)
		}

		// Create an unreadable directory
		unreadableDir := filepath.Join(tmpDir, "unreadable")
		err = os.MkdirAll(unreadableDir, 0755)
		if err != nil {
			t.Fatalf("failed to create unreadable directory: %v", err)
		}

		// Make the directory unreadable
		err = os.Chmod(unreadableDir, 0000)
		if err != nil {
			t.Fatalf("failed to change directory permissions: %v", err)
		}
		defer os.Chmod(unreadableDir, 0755) // Restore permissions for cleanup

		// Capture stderr to check for warning messages
		origStderr := os.Stderr
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("failed to create pipe: %v", err)
		}
		os.Stderr = w

		// Test recursive scan (should continue despite unreadable directory)
		result, err := Generate(tmpDir, true)

		// Restore stderr
		w.Close()
		os.Stderr = origStderr

		// Read captured stderr
		stderrOutput := make([]byte, 1024)
		n, _ := r.Read(stderrOutput)
		r.Close()
		stderrStr := string(stderrOutput[:n])

		// Should succeed and find the readable module
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 1 {
			t.Errorf("len(result.Modules) = %v, want 1", len(result.Modules))
		}

		if result.Modules[0].Name != "readable_module" {
			t.Errorf("module name = %v, want 'readable_module'", result.Modules[0].Name)
		}

		// Should have warning message in stderr
		if !strings.Contains(stderrStr, "Warning: skipping") {
			t.Errorf("Expected warning message in stderr, got: %s", stderrStr)
		}
	})

	// Test recursive scan skips hidden directories
	t.Run("recursive scan skips hidden directories", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_hidden_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create a normal directory with terraform config
		normalDir := filepath.Join(tmpDir, "normal")
		err = os.MkdirAll(normalDir, 0755)
		if err != nil {
			t.Fatalf("failed to create normal directory: %v", err)
		}

		normalConfig := `
module "normal_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
`
		err = os.WriteFile(filepath.Join(normalDir, "main.tf"), []byte(normalConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write normal config: %v", err)
		}

		// Create hidden directories that should be skipped
		hiddenDirs := []string{".terraform", ".git", ".vscode", ".idea"}
		for _, hiddenDir := range hiddenDirs {
			dir := filepath.Join(tmpDir, hiddenDir)
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				t.Fatalf("failed to create hidden directory %s: %v", hiddenDir, err)
			}

			// Add terraform files to hidden directories (should be ignored)
			hiddenConfig := `
module "hidden_module" {
  source = "should-be-ignored"
}
`
			err = os.WriteFile(filepath.Join(dir, "main.tf"), []byte(hiddenConfig), 0644)
			if err != nil {
				t.Fatalf("failed to write hidden config: %v", err)
			}
		}

		// Create nested hidden directory
		nestedHidden := filepath.Join(tmpDir, "normal", ".terraform", "modules")
		err = os.MkdirAll(nestedHidden, 0755)
		if err != nil {
			t.Fatalf("failed to create nested hidden directory: %v", err)
		}

		nestedConfig := `
module "nested_hidden" {
  source = "should-also-be-ignored"
}
`
		err = os.WriteFile(filepath.Join(nestedHidden, "main.tf"), []byte(nestedConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write nested hidden config: %v", err)
		}

		// Test recursive scan
		result, err := Generate(tmpDir, true)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		// Should only find the normal module, not any from hidden directories
		if len(result.Modules) != 1 {
			t.Errorf("len(result.Modules) = %v, want 1", len(result.Modules))
		}

		if result.Modules[0].Name != "normal_module" {
			t.Errorf("module name = %v, want 'normal_module'", result.Modules[0].Name)
		}

		// Verify no hidden modules were found
		for _, module := range result.Modules {
			if module.Name == "hidden_module" || module.Name == "nested_hidden" {
				t.Errorf("Found module from hidden directory: %s", module.Name)
			}
		}
	})

	// Test when root directory itself starts with dot
	t.Run("root directory starting with dot", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Create a subdirectory that starts with dot to be our "root"
		dotRoot := filepath.Join(tmpDir, ".myproject")
		err = os.MkdirAll(dotRoot, 0755)
		if err != nil {
			t.Fatalf("failed to create dot root directory: %v", err)
		}

		// Add terraform config to the dot root
		rootConfig := `
module "root_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}
`
		err = os.WriteFile(filepath.Join(dotRoot, "main.tf"), []byte(rootConfig), 0644)
		if err != nil {
			t.Fatalf("failed to write root config: %v", err)
		}

		// Test recursive scan starting from dot directory
		result, err := Generate(dotRoot, true)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		// Should find the module in the root dot directory
		if len(result.Modules) != 1 {
			t.Errorf("len(result.Modules) = %v, want 1", len(result.Modules))
		}

		if result.Modules[0].Name != "root_module" {
			t.Errorf("module name = %v, want 'root_module'", result.Modules[0].Name)
		}
	})

	// Test filename extraction from various file paths
	t.Run("filename extraction from various paths", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_filename_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		// Test different file names that might contain modules
		testFiles := map[string]string{
			"main.tf": `
module "main_module" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}`,
			"variables.tf": `
module "vars_module" {
  source = "./modules/local"
}`,
			"outputs.tf": `
module "outputs_module" {
  source = "github.com/example/module"
}`,
		}

		for filename, content := range testFiles {
			err = os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
			if err != nil {
				t.Fatalf("failed to write %s: %v", filename, err)
			}
		}

		result, err := Generate(tmpDir, false)
		if err != nil {
			t.Fatalf("Generate() = %v, want nil", err)
		}

		if len(result.Modules) != 3 {
			t.Errorf("len(result.Modules) = %v, want 3", len(result.Modules))
		}

		// Verify each module has correct filename extracted
		modulesByName := make(map[string]ModuleInfo)
		for _, module := range result.Modules {
			modulesByName[module.Name] = module

			// Verify filename is not empty and contains full path
			if module.Filename == "" {
				t.Errorf("Module %s has empty filename", module.Name)
			}
		}

		// Check specific filename extraction - should contain full path ending with expected file
		if mainMod, exists := modulesByName["main_module"]; exists {
			if !strings.HasSuffix(mainMod.Filename, "/main.tf") {
				t.Errorf("main_module.Filename = %v, want path ending with '/main.tf'", mainMod.Filename)
			}
		} else {
			t.Error("main_module not found")
		}

		if varsMod, exists := modulesByName["vars_module"]; exists {
			if !strings.HasSuffix(varsMod.Filename, "/variables.tf") {
				t.Errorf("vars_module.Filename = %v, want path ending with '/variables.tf'", varsMod.Filename)
			}
		} else {
			t.Error("vars_module not found")
		}

		if outputsMod, exists := modulesByName["outputs_module"]; exists {
			if !strings.HasSuffix(outputsMod.Filename, "/outputs.tf") {
				t.Errorf("outputs_module.Filename = %v, want path ending with '/outputs.tf'", outputsMod.Filename)
			}
		} else {
			t.Error("outputs_module not found")
		}
	})
}
