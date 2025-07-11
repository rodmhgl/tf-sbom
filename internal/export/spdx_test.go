package export

import (
	"fmt"
	"strings"
	"testing"
	"time"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"rodstewart/terraform-sbom/internal/sbom"
)

func TestConvertToSPDX(t *testing.T) {
	t.Run("empty SBOM", func(t *testing.T) {
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		doc := ConvertToSPDX(sbom)

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

		doc := ConvertToSPDX(sbom)

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

		doc := ConvertToSPDX(sbom)

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

		doc := ConvertToSPDX(sbom)

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

		doc := ConvertToSPDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules: []sbom.ModuleInfo{
				{Name: "module1", Source: "source1", Version: "v1", Location: "loc1"},
				{Name: "module2", Source: "source2", Version: "v2", Location: "loc2"},
				{Name: "module3", Source: "source3", Version: "v3", Location: "loc3"},
				{Name: "module4", Source: "source4", Version: "v4", Location: "loc4"},
				{Name: "module5", Source: "source5", Version: "v5", Location: "loc5"},
			},
		}

		doc := ConvertToSPDX(sbom)

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
		sbom := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		doc := ConvertToSPDX(sbom)

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
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at main.tf:20",
			},
		},
	}

	t.Run("successful SPDX export", func(t *testing.T) {
		var buffer strings.Builder
		err := SPDX(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("SPDX() = %v, want nil", err)
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
		emptySBOM := &sbom.SBOM{
			Version:   "1.0",
			Generated: time.Now().Format(time.RFC3339),
			Tool:      "terraform-sbom",
			Modules:   []sbom.ModuleInfo{},
		}

		var buffer strings.Builder
		err := SPDX(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("SPDX() = %v, want nil", err)
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
