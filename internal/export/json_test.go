package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"rodstewart/terraform-sbom/internal/sbom"
)

// failingWriter is a writer that always returns an error
type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("write operation failed")
}

func TestExportJSONErrors(t *testing.T) {
	// Test write error by using a failing writer
	t.Run("write error", func(t *testing.T) {
		testSBOM := &sbom.SBOM{
			Modules: []sbom.ModuleInfo{
				{Name: "test", Source: "test", Version: "1.0", Location: "test", Filename: "/project/test.tf"},
			},
		}

		// Use a writer that always fails
		failingWriter := &failingWriter{}
		err := JSON(testSBOM, failingWriter)
		if err == nil {
			t.Error("JSON() = nil, want error for failing writer")
		}
		if !strings.Contains(err.Error(), "failed to encode SBOM as JSON") {
			t.Errorf("error message = %v, want 'failed to encode SBOM as JSON'", err.Error())
		}
	})
}

func TestExportJSON(t *testing.T) {
	testSBOM := &sbom.SBOM{
		Modules: []sbom.ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at /project/main.tf:10",
				Filename: "/project/main.tf",
			},
		},
	}

	t.Run("successful JSON export", func(t *testing.T) {
		var buffer strings.Builder
		err := JSON(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("JSON() = %v, want nil", err)
		}

		// Verify JSON structure
		var parsedSBOM sbom.SBOM
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
		emptySBOM := &sbom.SBOM{Modules: []sbom.ModuleInfo{}}
		var buffer strings.Builder
		err := JSON(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("JSON() = %v, want nil", err)
		}

		var parsedSBOM sbom.SBOM
		err = json.Unmarshal([]byte(buffer.String()), &parsedSBOM)
		if err != nil {
			t.Fatalf("failed to parse JSON output: %v", err)
		}

		if len(parsedSBOM.Modules) != 0 {
			t.Errorf("len(parsedSBOM.Modules) = %v, want 0", len(parsedSBOM.Modules))
		}
	})
}
