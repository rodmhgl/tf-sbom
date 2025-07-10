package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
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

		err = validateTerraformDirectory(tmpDir)
		if err != nil {
			t.Errorf("validateTerraformDirectory() = %v, want nil", err)
		}
	})

	// Test with non-existing path
	t.Run("non-existing path", func(t *testing.T) {
		err := validateTerraformDirectory("/path/that/does/not/exist")
		if err == nil {
			t.Error("validateTerraformDirectory() = nil, want error")
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

		err = validateTerraformDirectory(tmpFile.Name())
		if err == nil {
			t.Error("validateTerraformDirectory() = nil, want error for file")
		}
		if !strings.Contains(err.Error(), "path must be a directory containing Terraform files") {
			t.Errorf("error message = %v, want 'path must be a directory containing Terraform files'", err.Error())
		}
	})
}

func TestModuleInfoSerialization(t *testing.T) {
	moduleInfo := ModuleInfo{
		Name:     "test-module",
		Source:   "github.com/example/test-module",
		Version:  "1.0.0",
		Location: "Module call at main.tf:10",
	}

	// Test JSON serialization
	t.Run("JSON serialization", func(t *testing.T) {
		jsonData, err := json.Marshal(moduleInfo)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}

		var unmarshaled ModuleInfo
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if unmarshaled.Name != moduleInfo.Name {
			t.Errorf("Name = %v, want %v", unmarshaled.Name, moduleInfo.Name)
		}
		if unmarshaled.Source != moduleInfo.Source {
			t.Errorf("Source = %v, want %v", unmarshaled.Source, moduleInfo.Source)
		}
		if unmarshaled.Version != moduleInfo.Version {
			t.Errorf("Version = %v, want %v", unmarshaled.Version, moduleInfo.Version)
		}
		if unmarshaled.Location != moduleInfo.Location {
			t.Errorf("Location = %v, want %v", unmarshaled.Location, moduleInfo.Location)
		}
	})

	// Test XML serialization
	t.Run("XML serialization", func(t *testing.T) {
		xmlData, err := xml.Marshal(moduleInfo)
		if err != nil {
			t.Fatalf("failed to marshal XML: %v", err)
		}

		var unmarshaled ModuleInfo
		err = xml.Unmarshal(xmlData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal XML: %v", err)
		}

		if unmarshaled.Name != moduleInfo.Name {
			t.Errorf("Name = %v, want %v", unmarshaled.Name, moduleInfo.Name)
		}
		if unmarshaled.Source != moduleInfo.Source {
			t.Errorf("Source = %v, want %v", unmarshaled.Source, moduleInfo.Source)
		}
		if unmarshaled.Version != moduleInfo.Version {
			t.Errorf("Version = %v, want %v", unmarshaled.Version, moduleInfo.Version)
		}
		if unmarshaled.Location != moduleInfo.Location {
			t.Errorf("Location = %v, want %v", unmarshaled.Location, moduleInfo.Location)
		}
	})
}

func TestSBOMSerialization(t *testing.T) {
	sbom := SBOM{
		Modules: []ModuleInfo{
			{
				Name:     "module1",
				Source:   "github.com/example/module1",
				Version:  "1.0.0",
				Location: "Module call at main.tf:10",
			},
			{
				Name:     "module2",
				Source:   "github.com/example/module2",
				Version:  "2.0.0",
				Location: "Module call at main.tf:20",
			},
		},
	}

	// Test JSON serialization
	t.Run("JSON serialization", func(t *testing.T) {
		jsonData, err := json.Marshal(sbom)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}

		var unmarshaled SBOM
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if len(unmarshaled.Modules) != len(sbom.Modules) {
			t.Errorf("Modules length = %v, want %v", len(unmarshaled.Modules), len(sbom.Modules))
		}

		for i, module := range unmarshaled.Modules {
			if module.Name != sbom.Modules[i].Name {
				t.Errorf("Module[%d].Name = %v, want %v", i, module.Name, sbom.Modules[i].Name)
			}
		}
	})

	// Test XML serialization
	t.Run("XML serialization", func(t *testing.T) {
		xmlData, err := xml.Marshal(sbom)
		if err != nil {
			t.Fatalf("failed to marshal XML: %v", err)
		}

		var unmarshaled SBOM
		err = xml.Unmarshal(xmlData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal XML: %v", err)
		}

		if len(unmarshaled.Modules) != len(sbom.Modules) {
			t.Errorf("Modules length = %v, want %v", len(unmarshaled.Modules), len(sbom.Modules))
		}

		for i, module := range unmarshaled.Modules {
			if module.Name != sbom.Modules[i].Name {
				t.Errorf("Module[%d].Name = %v, want %v", i, module.Name, sbom.Modules[i].Name)
			}
		}
	})
}

func TestGenerateSBOM(t *testing.T) {
	// Test with non-existing directory
	t.Run("non-existing directory", func(t *testing.T) {
		_, err := generateSBOM("/path/that/does/not/exist", false)
		if err == nil {
			t.Error("generateSBOM() = nil, want error")
		}
	})

	// Test with valid but empty directory
	t.Run("empty directory", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_terraform_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		sbom, err := generateSBOM(tmpDir, false)
		if err != nil {
			t.Fatalf("generateSBOM() = %v, want nil", err)
		}

		if len(sbom.Modules) != 0 {
			t.Errorf("len(sbom.Modules) = %v, want 0", len(sbom.Modules))
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

		sbom, err := generateSBOM(tmpDir, false)
		if err != nil {
			t.Fatalf("generateSBOM() = %v, want nil", err)
		}

		if len(sbom.Modules) != 2 {
			t.Errorf("len(sbom.Modules) = %v, want 2", len(sbom.Modules))
		}

		// Verify module details
		moduleNames := make(map[string]bool)
		for _, module := range sbom.Modules {
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

		_, err = generateSBOM(tmpDir, false)
		if err == nil {
			t.Error("generateSBOM() = nil, want error for invalid configuration")
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

		sbom, err := generateSBOM(tmpDir, false)
		if err != nil {
			t.Fatalf("generateSBOM() = %v, want nil", err)
		}

		if len(sbom.Modules) != 4 {
			t.Errorf("len(sbom.Modules) = %v, want 4", len(sbom.Modules))
		}

		// Verify each module type
		modulesByName := make(map[string]ModuleInfo)
		for _, module := range sbom.Modules {
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

		sbom, err := generateSBOM(tmpDir, false)
		if err != nil {
			t.Fatalf("generateSBOM() = %v, want nil", err)
		}

		if len(sbom.Modules) != 2 {
			t.Errorf("len(sbom.Modules) = %v, want 2", len(sbom.Modules))
		}

		// Verify modules with special characters and long names
		moduleNames := make(map[string]bool)
		for _, module := range sbom.Modules {
			moduleNames[module.Name] = true
			// Ensure all modules have valid configuration information
			if module.Location == "" {
				t.Errorf("Module %s has empty location", module.Name)
			}
		}

		if !moduleNames["special-chars_123"] {
			t.Error("Expected special-chars_123 module not found")
		}
		if !moduleNames["long_module_name_with_many_underscores_and_dashes"] {
			t.Error("Expected long_module_name_with_many_underscores_and_dashes module not found")
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

		_, err = generateSBOM(tmpFile.Name(), false)
		if err == nil {
			t.Error("generateSBOM() = nil, want error for file instead of directory")
		}
		if !strings.Contains(err.Error(), "path must be a directory containing Terraform files") {
			t.Errorf("error message = %v, want 'path must be a directory containing Terraform files'", err.Error())
		}
	})
}

func TestExportSBOM(t *testing.T) {
	// Create test SBOM
	testSBOM := &SBOM{
		Modules: []ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
			},
			{
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at main.tf:20",
			},
		},
	}

	// Test successful JSON export
	t.Run("successful JSON export", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.json")
		err = exportSBOM(testSBOM, "json", outputPath)
		if err != nil {
			t.Fatalf("exportSBOM() = %v, want nil", err)
		}

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("Output file was not created")
		}

		// Verify file contents
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		// Parse JSON to verify structure
		var parsedSBOM SBOM
		err = json.Unmarshal(content, &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(parsedSBOM.Modules) != 2 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 2", len(parsedSBOM.Modules))
		}

		// Verify pretty printing (should contain newlines and indentation)
		contentStr := string(content)
		if !strings.Contains(contentStr, "\n") {
			t.Error("JSON output should be pretty-printed with newlines")
		}
		if !strings.Contains(contentStr, "  ") {
			t.Error("JSON output should be indented")
		}
	})

	// Test input validation
	t.Run("nil SBOM", func(t *testing.T) {
		err := exportSBOM(nil, "json", "output.json")
		if err == nil {
			t.Error("exportSBOM() = nil, want error for nil SBOM")
		}
		if !strings.Contains(err.Error(), "sbom cannot be nil") {
			t.Errorf("error message = %v, want 'sbom cannot be nil'", err.Error())
		}
	})

	t.Run("empty format", func(t *testing.T) {
		err := exportSBOM(testSBOM, "", "output.json")
		if err == nil {
			t.Error("exportSBOM() = nil, want error for empty format")
		}
		if !strings.Contains(err.Error(), "format cannot be empty") {
			t.Errorf("error message = %v, want 'format cannot be empty'", err.Error())
		}
	})

	t.Run("empty output path", func(t *testing.T) {
		err := exportSBOM(testSBOM, "json", "")
		if err == nil {
			t.Error("exportSBOM() = nil, want error for empty output path")
		}
		if !strings.Contains(err.Error(), "output path cannot be empty") {
			t.Errorf("error message = %v, want 'output path cannot be empty'", err.Error())
		}
	})

	t.Run("unsupported format yaml", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.yaml")
		err = exportSBOM(testSBOM, "yaml", outputPath)
		if err == nil {
			t.Error("exportSBOM() = nil, want error for unsupported format")
		}

		expectedError := "unsupported format: yaml (supported: json, xml, spdx, cyclonedx)"
		if err.Error() != expectedError {
			t.Errorf("error message = %v, want %v", err.Error(), expectedError)
		}
	})

	t.Run("unsupported format csv", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.csv")
		err = exportSBOM(testSBOM, "csv", outputPath)
		if err == nil {
			t.Error("exportSBOM() = nil, want error for unsupported format")
		}

		expectedError := "unsupported format: csv (supported: json, xml, spdx, cyclonedx)"
		if err.Error() != expectedError {
			t.Errorf("error message = %v, want %v", err.Error(), expectedError)
		}
	})

	// Test successful XML export
	t.Run("successful XML export", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.xml")
		err = exportSBOM(testSBOM, "xml", outputPath)
		if err != nil {
			t.Fatalf("exportSBOM() = %v, want nil", err)
		}

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("Output file was not created")
		}

		// Verify file contents
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read output file: %v", err)
		}

		// Parse XML to verify structure
		var parsedSBOM SBOM
		err = xml.Unmarshal(content, &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse XML output: %v", err)
		}

		if len(parsedSBOM.Modules) != 2 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 2", len(parsedSBOM.Modules))
		}

		// Verify pretty printing (should contain newlines and indentation)
		contentStr := string(content)
		if !strings.Contains(contentStr, "\n") {
			t.Error("XML output should be pretty-printed with newlines")
		}
		if !strings.Contains(contentStr, "  ") {
			t.Error("XML output should be indented")
		}

		// Verify XML structure
		if !strings.Contains(contentStr, "<SBOM") {
			t.Error("XML should contain <SBOM> root element")
		}
		if !strings.Contains(contentStr, "<Modules>") {
			t.Error("XML should contain <Modules> element")
		}
		if !strings.Contains(contentStr, "<Module>") {
			t.Error("XML should contain <Module> elements")
		}
	})

	// Test file creation errors
	t.Run("invalid output path", func(t *testing.T) {
		err := exportSBOM(testSBOM, "json", "/invalid/path/that/does/not/exist/sbom.json")
		if err == nil {
			t.Error("exportSBOM() = nil, want error for invalid output path")
		}
		if !strings.Contains(err.Error(), "failed to create output file") {
			t.Errorf("error message = %v, want 'failed to create output file'", err.Error())
		}
	})
}

func TestExportJSON(t *testing.T) {
	testSBOM := &SBOM{
		Modules: []ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
			},
		},
	}

	t.Run("successful JSON export", func(t *testing.T) {
		var buffer strings.Builder
		err := exportJSON(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportJSON() = %v, want nil", err)
		}

		// Verify JSON structure
		var parsedSBOM SBOM
		err = json.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(parsedSBOM.Modules) != 1 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 1", len(parsedSBOM.Modules))
		}

		module := parsedSBOM.Modules[0]
		if module.Name != "test-module" {
			t.Errorf("module.Name = %v, want 'test-module'", module.Name)
		}
		if module.Source != "terraform-aws-modules/vpc/aws" {
			t.Errorf("module.Source = %v, want 'terraform-aws-modules/vpc/aws'", module.Source)
		}
		if module.Version != "~> 5.0" {
			t.Errorf("module.Version = %v, want '~> 5.0'", module.Version)
		}
	})

	t.Run("empty SBOM", func(t *testing.T) {
		emptySBOM := &SBOM{Modules: []ModuleInfo{}}
		var buffer strings.Builder
		err := exportJSON(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("exportJSON() = %v, want nil", err)
		}

		var parsedSBOM SBOM
		err = json.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(parsedSBOM.Modules) != 0 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 0", len(parsedSBOM.Modules))
		}
	})
}

func TestExportXML(t *testing.T) {
	testSBOM := &SBOM{
		Modules: []ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
			},
			{
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at main.tf:20",
			},
		},
	}

	t.Run("successful XML export", func(t *testing.T) {
		var buffer strings.Builder
		err := exportXML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		// Verify XML structure
		var parsedSBOM SBOM
		err = xml.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse XML output: %v", err)
		}

		if len(parsedSBOM.Modules) != 2 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 2", len(parsedSBOM.Modules))
		}

		// Verify module details
		modules := parsedSBOM.Modules
		if modules[0].Name != "test-module" {
			t.Errorf("modules[0].Name = %v, want 'test-module'", modules[0].Name)
		}
		if modules[0].Source != "terraform-aws-modules/vpc/aws" {
			t.Errorf("modules[0].Source = %v, want 'terraform-aws-modules/vpc/aws'", modules[0].Source)
		}
		if modules[0].Version != "~> 5.0" {
			t.Errorf("modules[0].Version = %v, want '~> 5.0'", modules[0].Version)
		}
		if modules[0].Location != "Module call at main.tf:10" {
			t.Errorf("modules[0].Location = %v, want 'Module call at main.tf:10'", modules[0].Location)
		}

		// Verify second module (without version)
		if modules[1].Name != "local-module" {
			t.Errorf("modules[1].Name = %v, want 'local-module'", modules[1].Name)
		}
		if modules[1].Source != "./modules/local" {
			t.Errorf("modules[1].Source = %v, want './modules/local'", modules[1].Source)
		}
		if modules[1].Version != "" {
			t.Errorf("modules[1].Version = %v, want empty string", modules[1].Version)
		}
	})

	t.Run("XML structure validation", func(t *testing.T) {
		var buffer strings.Builder
		err := exportXML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		xmlStr := buffer.String()

		// Check for proper XML hierarchy
		if !strings.Contains(xmlStr, "<SBOM") {
			t.Error("XML should contain <SBOM> root element")
		}
		if !strings.Contains(xmlStr, "</SBOM>") {
			t.Error("XML should contain closing </SBOM> element")
		}
		if !strings.Contains(xmlStr, "<Modules>") {
			t.Error("XML should contain <Modules> element")
		}
		if !strings.Contains(xmlStr, "</Modules>") {
			t.Error("XML should contain closing </Modules> element")
		}
		if !strings.Contains(xmlStr, "<Module>") {
			t.Error("XML should contain <Module> elements")
		}
		if !strings.Contains(xmlStr, "</Module>") {
			t.Error("XML should contain closing </Module> elements")
		}

		// Check for all expected fields
		if !strings.Contains(xmlStr, "<name>") {
			t.Error("XML should contain <name> elements")
		}
		if !strings.Contains(xmlStr, "<source>") {
			t.Error("XML should contain <source> elements")
		}
		if !strings.Contains(xmlStr, "<version>") {
			t.Error("XML should contain <version> elements")
		}
		if !strings.Contains(xmlStr, "<location>") {
			t.Error("XML should contain <location> elements")
		}

		// Check for specific values
		if !strings.Contains(xmlStr, "<name>test-module</name>") {
			t.Error("XML should contain test-module name")
		}
		if !strings.Contains(xmlStr, "<source>terraform-aws-modules/vpc/aws</source>") {
			t.Error("XML should contain terraform-aws-modules/vpc/aws source")
		}
	})

	t.Run("XML pretty printing", func(t *testing.T) {
		var buffer strings.Builder
		err := exportXML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		xmlStr := buffer.String()

		// Verify pretty printing (should contain newlines and indentation)
		if !strings.Contains(xmlStr, "\n") {
			t.Error("XML output should be pretty-printed with newlines")
		}
		if !strings.Contains(xmlStr, "  ") {
			t.Error("XML output should be indented")
		}

		// Check for proper indentation structure
		lines := strings.Split(xmlStr, "\n")
		var foundIndentedLine bool
		for _, line := range lines {
			if strings.HasPrefix(line, "  ") {
				foundIndentedLine = true
				break
			}
		}
		if !foundIndentedLine {
			t.Error("XML should have properly indented lines")
		}
	})

	t.Run("empty SBOM XML", func(t *testing.T) {
		emptySBOM := &SBOM{Modules: []ModuleInfo{}}
		var buffer strings.Builder
		err := exportXML(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		var parsedSBOM SBOM
		err = xml.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse XML output: %v", err)
		}

		if len(parsedSBOM.Modules) != 0 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 0", len(parsedSBOM.Modules))
		}

		xmlStr := buffer.String()
		// Should still have proper structure even when empty
		if !strings.Contains(xmlStr, "<SBOM") {
			t.Error("Empty XML should still contain <SBOM> root element")
		}
		if !strings.Contains(xmlStr, "<Modules>") {
			t.Error("Empty XML should still contain <Modules> element")
		}
	})

	t.Run("single module XML", func(t *testing.T) {
		singleModuleSBOM := &SBOM{
			Modules: []ModuleInfo{
				{
					Name:     "single-module",
					Source:   "github.com/example/module",
					Version:  "v1.0.0",
					Location: "Module call at test.tf:5",
				},
			},
		}

		var buffer strings.Builder
		err := exportXML(singleModuleSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		var parsedSBOM SBOM
		err = xml.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse XML output: %v", err)
		}

		if len(parsedSBOM.Modules) != 1 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 1", len(parsedSBOM.Modules))
		}

		module := parsedSBOM.Modules[0]
		if module.Name != "single-module" {
			t.Errorf("module.Name = %v, want 'single-module'", module.Name)
		}
		if module.Source != "github.com/example/module" {
			t.Errorf("module.Source = %v, want 'github.com/example/module'", module.Source)
		}
		if module.Version != "v1.0.0" {
			t.Errorf("module.Version = %v, want 'v1.0.0'", module.Version)
		}
	})

	t.Run("XML header validation", func(t *testing.T) {
		var buffer strings.Builder
		err := exportXML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportXML() = %v, want nil", err)
		}

		xmlStr := buffer.String()

		// Check for XML declaration header
		if !strings.HasPrefix(xmlStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
			t.Error("XML output should start with XML declaration header")
		}

		// Ensure header is on its own line
		if !strings.Contains(xmlStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n") {
			t.Error("XML header should be followed by newline")
		}

		// Verify the header comes before the SBOM element
		headerPos := strings.Index(xmlStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
		sbomPos := strings.Index(xmlStr, "<SBOM")
		if headerPos == -1 || sbomPos == -1 || headerPos >= sbomPos {
			t.Error("XML header should appear before SBOM element")
		}
	})
}

func TestConvertToSPDX(t *testing.T) {
	t.Run("empty SBOM", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		doc := convertToSPDX(sbom)

		// Verify basic SPDX document structure
		if doc.SPDXVersion != "SPDX-2.3" {
			t.Errorf("SPDXVersion = %v, want SPDX-2.3", doc.SPDXVersion)
		}
		if doc.DataLicense != "CC0-1.0" {
			t.Errorf("DataLicense = %v, want CC0-1.0", doc.DataLicense)
		}
		if doc.SPDXIdentifier != "SPDXRef-DOCUMENT" {
			t.Errorf("SPDXIdentifier = %v, want SPDXRef-DOCUMENT", doc.SPDXIdentifier)
		}
		if doc.DocumentName != "Terraform Configuration SBOM" {
			t.Errorf("DocumentName = %v, want 'Terraform Configuration SBOM'", doc.DocumentName)
		}

		// Verify DocumentNamespace format
		if !strings.HasPrefix(doc.DocumentNamespace, "https://terraform-sbom.local/") {
			t.Errorf("DocumentNamespace = %v, want to start with https://terraform-sbom.local/", doc.DocumentNamespace)
		}

		// Verify CreationInfo
		if doc.CreationInfo == nil {
			t.Fatal("CreationInfo should not be nil")
		}
		if doc.CreationInfo.Created == "" {
			t.Error("Created timestamp should not be empty")
		}
		if len(doc.CreationInfo.Creators) != 1 {
			t.Errorf("len(Creators) = %v, want 1", len(doc.CreationInfo.Creators))
		}
		if doc.CreationInfo.Creators[0].Creator != "Tool: terraform-sbom" {
			t.Errorf("Creator = %v, want 'Tool: terraform-sbom'", doc.CreationInfo.Creators[0].Creator)
		}

		// Verify empty packages
		if len(doc.Packages) != 0 {
			t.Errorf("len(Packages) = %v, want 0", len(doc.Packages))
		}
	})

	t.Run("single module with version", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "vpc",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
			},
		}

		doc := convertToSPDX(sbom)

		// Verify single package
		if len(doc.Packages) != 1 {
			t.Errorf("len(Packages) = %v, want 1", len(doc.Packages))
		}

		pkg := doc.Packages[0]
		if pkg.PackageName != "vpc" {
			t.Errorf("PackageName = %v, want 'vpc'", pkg.PackageName)
		}
		if pkg.PackageSPDXIdentifier != "SPDXRef-Package-0" {
			t.Errorf("PackageSPDXIdentifier = %v, want 'SPDXRef-Package-0'", pkg.PackageSPDXIdentifier)
		}
		if pkg.PackageDownloadLocation != "terraform-aws-modules/vpc/aws" {
			t.Errorf("PackageDownloadLocation = %v, want 'terraform-aws-modules/vpc/aws'", pkg.PackageDownloadLocation)
		}
		if pkg.PackageVersion != "~> 5.0" {
			t.Errorf("PackageVersion = %v, want '~> 5.0'", pkg.PackageVersion)
		}
		if pkg.PackageCopyrightText != "NOASSERTION" {
			t.Errorf("PackageCopyrightText = %v, want 'NOASSERTION'", pkg.PackageCopyrightText)
		}
	})

	t.Run("single module without version", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "local-module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:20",
				},
			},
		}

		doc := convertToSPDX(sbom)

		// Verify single package
		if len(doc.Packages) != 1 {
			t.Errorf("len(Packages) = %v, want 1", len(doc.Packages))
		}

		pkg := doc.Packages[0]
		if pkg.PackageName != "local-module" {
			t.Errorf("PackageName = %v, want 'local-module'", pkg.PackageName)
		}
		if pkg.PackageVersion != "NOASSERTION" {
			t.Errorf("PackageVersion = %v, want 'NOASSERTION'", pkg.PackageVersion)
		}
		if pkg.PackageDownloadLocation != "./modules/local" {
			t.Errorf("PackageDownloadLocation = %v, want './modules/local'", pkg.PackageDownloadLocation)
		}
	})

	t.Run("multiple modules", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "vpc",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
				{
					Name:     "security_group",
					Source:   "terraform-aws-modules/security-group/aws",
					Version:  "v4.17.1",
					Location: "Module call at main.tf:20",
				},
				{
					Name:     "local_module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:30",
				},
			},
		}

		doc := convertToSPDX(sbom)

		// Verify multiple packages
		if len(doc.Packages) != 3 {
			t.Errorf("len(Packages) = %v, want 3", len(doc.Packages))
		}

		// Verify first package
		pkg0 := doc.Packages[0]
		if pkg0.PackageName != "vpc" {
			t.Errorf("Packages[0].PackageName = %v, want 'vpc'", pkg0.PackageName)
		}
		if pkg0.PackageSPDXIdentifier != "SPDXRef-Package-0" {
			t.Errorf("Packages[0].PackageSPDXIdentifier = %v, want 'SPDXRef-Package-0'", pkg0.PackageSPDXIdentifier)
		}
		if pkg0.PackageVersion != "~> 5.0" {
			t.Errorf("Packages[0].PackageVersion = %v, want '~> 5.0'", pkg0.PackageVersion)
		}

		// Verify second package
		pkg1 := doc.Packages[1]
		if pkg1.PackageName != "security_group" {
			t.Errorf("Packages[1].PackageName = %v, want 'security_group'", pkg1.PackageName)
		}
		if pkg1.PackageSPDXIdentifier != "SPDXRef-Package-1" {
			t.Errorf("Packages[1].PackageSPDXIdentifier = %v, want 'SPDXRef-Package-1'", pkg1.PackageSPDXIdentifier)
		}
		if pkg1.PackageVersion != "v4.17.1" {
			t.Errorf("Packages[1].PackageVersion = %v, want 'v4.17.1'", pkg1.PackageVersion)
		}

		// Verify third package (no version)
		pkg2 := doc.Packages[2]
		if pkg2.PackageName != "local_module" {
			t.Errorf("Packages[2].PackageName = %v, want 'local_module'", pkg2.PackageName)
		}
		if pkg2.PackageSPDXIdentifier != "SPDXRef-Package-2" {
			t.Errorf("Packages[2].PackageSPDXIdentifier = %v, want 'SPDXRef-Package-2'", pkg2.PackageSPDXIdentifier)
		}
		if pkg2.PackageVersion != "NOASSERTION" {
			t.Errorf("Packages[2].PackageVersion = %v, want 'NOASSERTION'", pkg2.PackageVersion)
		}
		if pkg2.PackageDownloadLocation != "./modules/local" {
			t.Errorf("Packages[2].PackageDownloadLocation = %v, want './modules/local'", pkg2.PackageDownloadLocation)
		}

		// Verify all packages have required fields
		for i, pkg := range doc.Packages {
			if pkg.PackageCopyrightText != "NOASSERTION" {
				t.Errorf("Packages[%d].PackageCopyrightText = %v, want 'NOASSERTION'", i, pkg.PackageCopyrightText)
			}
		}
	})

	t.Run("different module source types", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "registry_module",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
				{
					Name:     "git_module",
					Source:   "git::https://github.com/example/terraform-module.git",
					Version:  "v1.0.0",
					Location: "Module call at main.tf:20",
				},
				{
					Name:     "local_module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:30",
				},
				{
					Name:     "github_module",
					Source:   "github.com/example/module",
					Version:  "",
					Location: "Module call at main.tf:40",
				},
			},
		}

		doc := convertToSPDX(sbom)

		if len(doc.Packages) != 4 {
			t.Errorf("len(Packages) = %v, want 4", len(doc.Packages))
		}

		// Create a map for easier testing
		packages := make(map[string]*v2_3.Package)
		for _, pkg := range doc.Packages {
			packages[pkg.PackageName] = pkg
		}

		// Test registry module
		if pkg, exists := packages["registry_module"]; exists {
			if pkg.PackageDownloadLocation != "terraform-aws-modules/vpc/aws" {
				t.Errorf("registry_module.PackageDownloadLocation = %v, want 'terraform-aws-modules/vpc/aws'", pkg.PackageDownloadLocation)
			}
			if pkg.PackageVersion != "~> 5.0" {
				t.Errorf("registry_module.PackageVersion = %v, want '~> 5.0'", pkg.PackageVersion)
			}
		} else {
			t.Error("registry_module not found in packages")
		}

		// Test git module
		if pkg, exists := packages["git_module"]; exists {
			if pkg.PackageDownloadLocation != "git::https://github.com/example/terraform-module.git" {
				t.Errorf("git_module.PackageDownloadLocation = %v, want 'git::https://github.com/example/terraform-module.git'", pkg.PackageDownloadLocation)
			}
			if pkg.PackageVersion != "v1.0.0" {
				t.Errorf("git_module.PackageVersion = %v, want 'v1.0.0'", pkg.PackageVersion)
			}
		} else {
			t.Error("git_module not found in packages")
		}

		// Test local module
		if pkg, exists := packages["local_module"]; exists {
			if pkg.PackageDownloadLocation != "./modules/local" {
				t.Errorf("local_module.PackageDownloadLocation = %v, want './modules/local'", pkg.PackageDownloadLocation)
			}
			if pkg.PackageVersion != "NOASSERTION" {
				t.Errorf("local_module.PackageVersion = %v, want 'NOASSERTION'", pkg.PackageVersion)
			}
		} else {
			t.Error("local_module not found in packages")
		}

		// Test github module
		if pkg, exists := packages["github_module"]; exists {
			if pkg.PackageDownloadLocation != "github.com/example/module" {
				t.Errorf("github_module.PackageDownloadLocation = %v, want 'github.com/example/module'", pkg.PackageDownloadLocation)
			}
			if pkg.PackageVersion != "NOASSERTION" {
				t.Errorf("github_module.PackageVersion = %v, want 'NOASSERTION'", pkg.PackageVersion)
			}
		} else {
			t.Error("github_module not found in packages")
		}
	})

	t.Run("SPDX identifier uniqueness", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{Name: "module1", Source: "source1", Version: "v1", Location: "loc1"},
				{Name: "module2", Source: "source2", Version: "v2", Location: "loc2"},
				{Name: "module3", Source: "source3", Version: "v3", Location: "loc3"},
				{Name: "module4", Source: "source4", Version: "v4", Location: "loc4"},
				{Name: "module5", Source: "source5", Version: "v5", Location: "loc5"},
			},
		}

		doc := convertToSPDX(sbom)

		// Verify unique SPDX identifiers
		identifiers := make(map[common.ElementID]bool)
		for i, pkg := range doc.Packages {
			expectedID := common.ElementID(fmt.Sprintf("SPDXRef-Package-%d", i))
			if pkg.PackageSPDXIdentifier != expectedID {
				t.Errorf("Packages[%d].PackageSPDXIdentifier = %v, want %v", i, pkg.PackageSPDXIdentifier, expectedID)
			}

			if identifiers[pkg.PackageSPDXIdentifier] {
				t.Errorf("Duplicate SPDX identifier found: %v", pkg.PackageSPDXIdentifier)
			}
			identifiers[pkg.PackageSPDXIdentifier] = true
		}

		// Verify we have the expected number of unique identifiers
		if len(identifiers) != 5 {
			t.Errorf("len(identifiers) = %v, want 5", len(identifiers))
		}
	})

	t.Run("timestamp format validation", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		doc := convertToSPDX(sbom)

		// Verify timestamp is in RFC3339 format
		_, err := time.Parse(time.RFC3339, doc.CreationInfo.Created)
		if err != nil {
			t.Errorf("Created timestamp parsing failed: %v", err)
		}

		// Verify namespace timestamp is in the expected format
		namespaceTime := strings.TrimPrefix(doc.DocumentNamespace, "https://terraform-sbom.local/")
		_, err = time.Parse("2006-01-02T15:04:05Z", namespaceTime)
		if err != nil {
			t.Errorf("DocumentNamespace timestamp parsing failed: %v", err)
		}
	})
}

func TestExportSPDX(t *testing.T) {
	testSBOM := &SBOM{
		Version:   "1.0",
		Generated: time.Now().Format(time.RFC3339),
		Tool:      "terraform-sbom",
		Modules: []ModuleInfo{
			{
				Name:     "vpc",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
			},
			{
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at main.tf:20",
			},
		},
	}

	t.Run("successful SPDX export", func(t *testing.T) {
		var buffer strings.Builder
		err := exportSPDX(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportSPDX() = %v, want nil", err)
		}

		// Verify output is valid JSON
		doc, err := spdxjson.Read(strings.NewReader(buffer.String()))
		if err != nil {
			t.Fatalf("failed to parse SPDX JSON output: %v", err)
		}

		// Verify SPDX document structure
		if doc.SPDXVersion != "SPDX-2.3" {
			t.Errorf("SPDXVersion = %v, want SPDX-2.3", doc.SPDXVersion)
		}
		if doc.DataLicense != "CC0-1.0" {
			t.Errorf("DataLicense = %v, want CC0-1.0", doc.DataLicense)
		}
		if doc.DocumentName != "Terraform Configuration SBOM" {
			t.Errorf("DocumentName = %v, want 'Terraform Configuration SBOM'", doc.DocumentName)
		}

		// Verify packages were converted correctly
		if len(doc.Packages) != 2 {
			t.Errorf("len(Packages) = %v, want 2", len(doc.Packages))
		}

		// Verify first package
		pkg0 := doc.Packages[0]
		if pkg0.PackageName != "vpc" {
			t.Errorf("Packages[0].PackageName = %v, want 'vpc'", pkg0.PackageName)
		}
		if pkg0.PackageVersion != "~> 5.0" {
			t.Errorf("Packages[0].PackageVersion = %v, want '~> 5.0'", pkg0.PackageVersion)
		}

		// Verify second package (no version)
		pkg1 := doc.Packages[1]
		if pkg1.PackageName != "local-module" {
			t.Errorf("Packages[1].PackageName = %v, want 'local-module'", pkg1.PackageName)
		}
		if pkg1.PackageVersion != "NOASSERTION" {
			t.Errorf("Packages[1].PackageVersion = %v, want 'NOASSERTION'", pkg1.PackageVersion)
		}
	})

	t.Run("empty SBOM SPDX export", func(t *testing.T) {
		emptySBOM := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		var buffer strings.Builder
		err := exportSPDX(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("exportSPDX() = %v, want nil", err)
		}

		// Verify output is valid JSON
		doc, err := spdxjson.Read(strings.NewReader(buffer.String()))
		if err != nil {
			t.Fatalf("failed to parse SPDX JSON output: %v", err)
		}

		// Verify empty packages
		if len(doc.Packages) != 0 {
			t.Errorf("len(Packages) = %v, want 0", len(doc.Packages))
		}
	})
}

func TestConvertToCycloneDX(t *testing.T) {
	t.Run("empty SBOM", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		bom := convertToCycloneDX(sbom)

		// Verify basic BOM structure
		if bom.BOMFormat != "CycloneDX" {
			t.Errorf("BOMFormat = %v, want CycloneDX", bom.BOMFormat)
		}
		if bom.SpecVersion != cyclonedx.SpecVersion1_6 {
			t.Errorf("SpecVersion = %v, want %v", bom.SpecVersion, cyclonedx.SpecVersion1_6)
		}
		if bom.Version != 1 {
			t.Errorf("Version = %v, want 1", bom.Version)
		}

		// Verify metadata
		if bom.Metadata == nil {
			t.Fatal("Metadata should not be nil")
		}
		if bom.Metadata.Timestamp == "" {
			t.Error("Timestamp should not be empty")
		}

		// Verify tools metadata
		if bom.Metadata.Tools == nil || bom.Metadata.Tools.Tools == nil {
			t.Fatal("Tools metadata should not be nil")
		}
		tools := *bom.Metadata.Tools.Tools
		if len(tools) != 1 {
			t.Errorf("len(Tools) = %v, want 1", len(tools))
		}
		if tools[0].Name != "terraform-sbom" {
			t.Errorf("Tool name = %v, want 'terraform-sbom'", tools[0].Name)
		}
		if tools[0].Version != "1.0.0" {
			t.Errorf("Tool version = %v, want '1.0.0'", tools[0].Version)
		}

		// Verify empty components
		if bom.Components == nil || len(*bom.Components) != 0 {
			t.Errorf("Components should be empty array, got %v", bom.Components)
		}
	})

	t.Run("single module with version", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "vpc",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
			},
		}

		bom := convertToCycloneDX(sbom)

		// Verify single component
		if bom.Components == nil || len(*bom.Components) != 1 {
			t.Errorf("len(Components) = %v, want 1", len(*bom.Components))
		}

		component := (*bom.Components)[0]
		if component.Type != cyclonedx.ComponentTypeLibrary {
			t.Errorf("Component.Type = %v, want %v", component.Type, cyclonedx.ComponentTypeLibrary)
		}
		if component.Name != "vpc" {
			t.Errorf("Component.Name = %v, want 'vpc'", component.Name)
		}
		if component.Version != "~> 5.0" {
			t.Errorf("Component.Version = %v, want '~> 5.0'", component.Version)
		}
		if component.Group != "terraform-aws-modules" {
			t.Errorf("Component.Group = %v, want 'terraform-aws-modules'", component.Group)
		}
	})

	t.Run("module without version", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "local-module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:20",
				},
			},
		}

		bom := convertToCycloneDX(sbom)

		component := (*bom.Components)[0]
		if component.Name != "local-module" {
			t.Errorf("Component.Name = %v, want 'local-module'", component.Name)
		}
		if component.Version != "" {
			t.Errorf("Component.Version = %v, want empty string", component.Version)
		}
		if component.Group != "." {
			t.Errorf("Component.Group = %v, want '.'", component.Group)
		}
	})

	t.Run("multiple modules with different sources", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []ModuleInfo{
				{
					Name:     "registry_module",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
				{
					Name:     "git_module",
					Source:   "git::https://github.com/example/terraform-module.git",
					Version:  "v1.0.0",
					Location: "Module call at main.tf:20",
				},
				{
					Name:     "local_module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:30",
				},
				{
					Name:     "github_module",
					Source:   "github.com/example/module",
					Version:  "",
					Location: "Module call at main.tf:40",
				},
			},
		}

		bom := convertToCycloneDX(sbom)

		if len(*bom.Components) != 4 {
			t.Errorf("len(Components) = %v, want 4", len(*bom.Components))
		}

		components := *bom.Components

		// Test registry module
		registryComp := components[0]
		if registryComp.Name != "registry_module" {
			t.Errorf("registry component name = %v, want 'registry_module'", registryComp.Name)
		}
		if registryComp.Group != "terraform-aws-modules" {
			t.Errorf("registry component group = %v, want 'terraform-aws-modules'", registryComp.Group)
		}

		// Test git module
		gitComp := components[1]
		if gitComp.Name != "git_module" {
			t.Errorf("git component name = %v, want 'git_module'", gitComp.Name)
		}
		if gitComp.Group != "git::https:" {
			t.Errorf("git component group = %v, want 'git::https:'", gitComp.Group)
		}

		// Test local module
		localComp := components[2]
		if localComp.Name != "local_module" {
			t.Errorf("local component name = %v, want 'local_module'", localComp.Name)
		}
		if localComp.Group != "." {
			t.Errorf("local component group = %v, want '.'", localComp.Group)
		}

		// Test github module
		githubComp := components[3]
		if githubComp.Name != "github_module" {
			t.Errorf("github component name = %v, want 'github_module'", githubComp.Name)
		}
		if githubComp.Group != "github.com" {
			t.Errorf("github component group = %v, want 'github.com'", githubComp.Group)
		}
	})

	t.Run("timestamp format validation", func(t *testing.T) {
		sbom := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		bom := convertToCycloneDX(sbom)

		// Verify timestamp is in RFC3339 format
		_, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp)
		if err != nil {
			t.Errorf("Timestamp parsing failed: %v", err)
		}
	})
}

func TestExportCycloneDX(t *testing.T) {
	testSBOM := &SBOM{
		Version:   "1.0",
		Generated: time.Now().Format(time.RFC3339),
		Tool:      "terraform-sbom",
		Modules: []ModuleInfo{
			{
				Name:     "vpc",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
			},
			{
				Name:     "security_group",
				Source:   "terraform-aws-modules/security-group/aws",
				Version:  "v4.17.1",
				Location: "Module call at main.tf:20",
			},
		},
	}

	t.Run("successful CycloneDX export", func(t *testing.T) {
		var buffer strings.Builder
		err := exportCycloneDX(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("exportCycloneDX() = %v, want nil", err)
		}

		// Verify output is valid JSON
		var bom cyclonedx.BOM
		err = json.Unmarshal([]byte(buffer.String()), &bom)
		if err != nil {
			t.Fatalf("failed to parse CycloneDX JSON output: %v", err)
		}

		// Verify BOM structure
		if bom.BOMFormat != "CycloneDX" {
			t.Errorf("BOMFormat = %v, want CycloneDX", bom.BOMFormat)
		}
		if bom.SpecVersion != cyclonedx.SpecVersion1_6 {
			t.Errorf("SpecVersion = %v, want %v", bom.SpecVersion, cyclonedx.SpecVersion1_6)
		}

		// Verify components were converted correctly
		if bom.Components == nil || len(*bom.Components) != 2 {
			t.Errorf("len(Components) = %v, want 2", len(*bom.Components))
		}

		components := *bom.Components

		// Verify first component
		comp0 := components[0]
		if comp0.Name != "vpc" {
			t.Errorf("Components[0].Name = %v, want 'vpc'", comp0.Name)
		}
		if comp0.Version != "~> 5.0" {
			t.Errorf("Components[0].Version = %v, want '~> 5.0'", comp0.Version)
		}
		if comp0.Group != "terraform-aws-modules" {
			t.Errorf("Components[0].Group = %v, want 'terraform-aws-modules'", comp0.Group)
		}

		// Verify second component
		comp1 := components[1]
		if comp1.Name != "security_group" {
			t.Errorf("Components[1].Name = %v, want 'security_group'", comp1.Name)
		}
		if comp1.Version != "v4.17.1" {
			t.Errorf("Components[1].Version = %v, want 'v4.17.1'", comp1.Version)
		}
	})

	t.Run("empty SBOM CycloneDX export", func(t *testing.T) {
		emptySBOM := &SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []ModuleInfo{},
		}

		var buffer strings.Builder
		err := exportCycloneDX(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("exportCycloneDX() = %v, want nil", err)
		}

		// Verify output is valid JSON
		var bom cyclonedx.BOM
		err = json.Unmarshal([]byte(buffer.String()), &bom)
		if err != nil {
			t.Fatalf("failed to parse CycloneDX JSON output: %v", err)
		}

		// Verify empty components
		if bom.Components == nil || len(*bom.Components) != 0 {
			t.Errorf("Components should be empty array, got %v", len(*bom.Components))
		}
	})
}

func TestGenerateOutputFilename(t *testing.T) {
	t.Run("empty base output - default filenames", func(t *testing.T) {
		tests := []struct {
			format   string
			expected string
		}{
			{"json", "sbom.json"},
			{"xml", "sbom.xml"},
			{"spdx", "sbom.spdx.json"},
			{"cyclonedx", "sbom.cyclonedx.json"},
			{"unknown", "sbom.json"},
			{"", "sbom.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename("", test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(\"\", %q) = %q, want %q", test.format, result, test.expected)
			}
		}
	})

	t.Run("base output without extension", func(t *testing.T) {
		tests := []struct {
			base     string
			format   string
			expected string
		}{
			{"mysbom", "json", "mysbom.json"},
			{"mysbom", "xml", "mysbom.xml"},
			{"mysbom", "spdx", "mysbom.spdx.json"},
			{"mysbom", "cyclonedx", "mysbom.cyclonedx.json"},
			{"mysbom", "unknown", "mysbom.json"},
			{"output", "json", "output.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})

	t.Run("base output with extension", func(t *testing.T) {
		tests := []struct {
			base     string
			format   string
			expected string
		}{
			{"mysbom.txt", "json", "mysbom.json"},
			{"mysbom.old", "xml", "mysbom.xml"},
			{"mysbom.bak", "spdx", "mysbom.spdx.json"},
			{"mysbom.tmp", "cyclonedx", "mysbom.cyclonedx.json"},
			{"output.backup", "json", "output.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})

	t.Run("base output with path", func(t *testing.T) {
		tests := []struct {
			base     string
			format   string
			expected string
		}{
			{"/path/to/mysbom", "json", "/path/to/mysbom.json"},
			{"./output/sbom", "xml", "./output/sbom.xml"},
			{"../reports/terraform", "spdx", "../reports/terraform.spdx.json"},
			{"dir/subdir/file.old", "cyclonedx", "dir/subdir/file.cyclonedx.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})

	t.Run("complex extensions", func(t *testing.T) {
		tests := []struct {
			base     string
			format   string
			expected string
		}{
			{"file.tar.gz", "json", "file.tar.json"},
			{"backup.2023.json", "xml", "backup.2023.xml"},
			{"myfile.spdx.json", "spdx", "myfile.spdx.spdx.json"},
			{"output.cyclonedx.json", "cyclonedx", "output.cyclonedx.cyclonedx.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})

	t.Run("edge cases", func(t *testing.T) {
		tests := []struct {
			base     string
			format   string
			expected string
		}{
			{".", "json", ".json"},
			{".hidden", "xml", ".xml"},
			{"file.", "spdx", "file.spdx.json"},
			{"no-extension", "cyclonedx", "no-extension.cyclonedx.json"},
		}

		for _, test := range tests {
			result := generateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("generateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})
}
