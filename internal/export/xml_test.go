package export

import (
	"encoding/xml"
	"fmt"
	"strings"
	"testing"

	"rodstewart/terraform-sbom/internal/sbom"
)

// headerWrittenFailingWriter allows the XML header to be written but fails on subsequent writes
type headerWrittenFailingWriter struct {
	headerWritten bool
}

func (hw *headerWrittenFailingWriter) Write(p []byte) (n int, err error) {
	if !hw.headerWritten && string(p) == xml.Header {
		hw.headerWritten = true
		return len(p), nil
	}
	return 0, fmt.Errorf("write operation failed after header")
}

func TestExportXMLErrors(t *testing.T) {
	// Test XML header write error
	t.Run("XML header write error", func(t *testing.T) {
		testSBOM := &sbom.SBOM{
			Modules: []sbom.ModuleInfo{
				{Name: "test", Source: "test", Version: "1.0", Location: "test", Filename: "/project/test.tf"},
			},
		}

		// Use a writer that always fails
		failingWriter := &failingWriter{}
		err := XML(testSBOM, failingWriter)
		if err == nil {
			t.Error("XML() = nil, want error for failing writer")
		}
		if !strings.Contains(err.Error(), "failed to write XML header") {
			t.Errorf("error message = %v, want 'failed to write XML header'", err.Error())
		}
	})

	// Test XML encoding error by using a failing writer after header
	t.Run("XML encoding error", func(t *testing.T) {
		testSBOM := &sbom.SBOM{
			Modules: []sbom.ModuleInfo{
				{Name: "test", Source: "test", Version: "1.0", Location: "test", Filename: "/project/test.tf"},
			},
		}

		// Use a writer that fails after the header is written
		headerWrittenWriter := &headerWrittenFailingWriter{}
		err := XML(testSBOM, headerWrittenWriter)
		if err == nil {
			t.Error("XML() = nil, want error for failing writer")
		}
		if !strings.Contains(err.Error(), "failed to encode SBOM as XML") {
			t.Errorf("error message = %v, want 'failed to encode SBOM as XML'", err.Error())
		}
	})
}

func TestExportXML(t *testing.T) {
	testSBOM := &sbom.SBOM{
		Modules: []sbom.ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at /project/main.tf:10",
				Filename: "/project/main.tf",
			},
			{
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at /project/main.tf:20",
				Filename: "/project/main.tf",
			},
		},
	}

	t.Run("successful XML export", func(t *testing.T) {
		var buffer strings.Builder
		err := XML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
		}

		// Verify XML structure
		var parsedSBOM sbom.SBOM
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
		err := XML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
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
		err := XML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
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
		emptySBOM := &sbom.SBOM{Modules: []sbom.ModuleInfo{}}
		var buffer strings.Builder
		err := XML(emptySBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
		}

		var parsedSBOM sbom.SBOM
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
		singleModuleSBOM := &sbom.SBOM{
			Modules: []sbom.ModuleInfo{
				{
					Name:     "single-module",
					Source:   "github.com/example/module",
					Version:  "v1.0.0",
					Location: "Module call at /project/test.tf:5",
					Filename: "/project/test.tf",
				},
			},
		}

		var buffer strings.Builder
		err := XML(singleModuleSBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
		}

		var parsedSBOM sbom.SBOM
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
		err := XML(testSBOM, &buffer)
		if err != nil {
			t.Fatalf("XML() = %v, want nil", err)
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
