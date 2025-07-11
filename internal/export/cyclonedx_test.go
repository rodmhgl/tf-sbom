package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"rodstewart/terraform-sbom/internal/sbom"
)

func TestConvertToCycloneDX(t *testing.T) {
	t.Run("empty SBOM", func(t *testing.T) {
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		bom := ConvertToCycloneDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []sbom.ModuleInfo{
				{
					Name:     "vpc",
					Source:   "terraform-aws-modules/vpc/aws",
					Version:  "~> 5.0",
					Location: "Module call at main.tf:10",
				},
			},
		}

		bom := ConvertToCycloneDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []sbom.ModuleInfo{
				{
					Name:     "local-module",
					Source:   "./modules/local",
					Version:  "",
					Location: "Module call at main.tf:20",
				},
			},
		}

		bom := ConvertToCycloneDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []sbom.ModuleInfo{
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

		bom := ConvertToCycloneDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		bom := ConvertToCycloneDX(sbom)

		// Verify timestamp is in RFC3339 format
		_, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp)
		if err != nil {
			t.Errorf("Timestamp parsing failed: %v", err)
		}
	})
}

func TestExportCycloneDX(t *testing.T) {
	testSBOM := &sbom.SBOM{
		Version:   "1.0",
		Generated: time.Now().Format(time.RFC3339),
		Tool:      "terraform-sbom",
		Modules: []sbom.ModuleInfo{
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
		err := CycloneDX(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("CycloneDX() = %v, want nil", err)
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
		emptySBOM := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		var buffer strings.Builder
		err := CycloneDX(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("CycloneDX() = %v, want nil", err)
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
