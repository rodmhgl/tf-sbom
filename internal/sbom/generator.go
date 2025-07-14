package sbom

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/hashicorp/terraform-config-inspect/tfconfig"
)

// Generate generates a Software Bill of Materials for a Terraform configuration
func Generate(configPath string, recursive bool) (*SBOM, error) {
	// Validate the configuration path exists
	if err := ValidateTerraformDirectory(configPath); err != nil {
		return nil, err
	}

	// Clean the path to ensure it's absolute
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Find all Terraform module directories
	moduleDirs, err := FindTerraformModules(absPath, recursive)
	if err != nil {
		return nil, fmt.Errorf("failed to find Terraform modules: %w", err)
	}

	// Create SBOM with initial structure
	sbom := &SBOM{
		Version:   "1.0",
		Generated: time.Now().Format(time.RFC3339),
		Tool:      "terraform-sbom",
		Modules:   []ModuleInfo{},
	}

	// Process each directory and collect all modules
	for _, moduleDir := range moduleDirs {
		module, diags := tfconfig.LoadModule(moduleDir)
		if diags.HasErrors() {
			return nil, fmt.Errorf("failed to load Terraform module from %s: %s", moduleDir, diags.Error())
		}

		// Convert each module call to ModuleInfo
		for _, moduleCall := range module.ModuleCalls {
			moduleInfo := ModuleInfo{
				Name:     moduleCall.Name,
				Source:   moduleCall.Source,
				Version:  moduleCall.Version,
				Location: fmt.Sprintf("Module call at %s:%d", moduleCall.Pos.Filename, moduleCall.Pos.Line),
				Filename: filepath.Base(moduleCall.Pos.Filename),
			}
			sbom.Modules = append(sbom.Modules, moduleInfo)
		}
	}

	return sbom, nil
}
