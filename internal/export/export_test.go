package export

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rodstewart/terraform-sbom/internal/sbom"
)

func TestExportSBOM(t *testing.T) {
	// Create test SBOM
	testSBOM := &sbom.SBOM{
		Modules: []sbom.ModuleInfo{
			{
				Name:     "test-module",
				Source:   "terraform-aws-modules/vpc/aws",
				Version:  "~> 5.0",
				Location: "Module call at main.tf:10",
				Filename: "main.tf",
			},
			{
				Name:     "local-module",
				Source:   "./modules/local",
				Version:  "",
				Location: "Module call at main.tf:20",
				Filename: "main.tf",
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
		err = Export(testSBOM, "json", outputPath)
		if err != nil {
			t.Fatalf("Export() = %v, want nil", err)
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
		var parsedSBOM sbom.SBOM
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
		err := Export(nil, "json", "output.json")
		if err == nil {
			t.Error("Export() = nil, want error for nil SBOM")
		}
		if !strings.Contains(err.Error(), "sbom cannot be nil") {
			t.Errorf("error message = %v, want 'sbom cannot be nil'", err.Error())
		}
	})

	t.Run("empty format", func(t *testing.T) {
		err := Export(testSBOM, "", "output.json")
		if err == nil {
			t.Error("Export() = nil, want error for empty format")
		}
		if !strings.Contains(err.Error(), "format cannot be empty") {
			t.Errorf("error message = %v, want 'format cannot be empty'", err.Error())
		}
	})

	t.Run("empty output path", func(t *testing.T) {
		err := Export(testSBOM, "json", "")
		if err == nil {
			t.Error("Export() = nil, want error for empty output path")
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
		err = Export(testSBOM, "yaml", outputPath)
		if err == nil {
			t.Error("Export() = nil, want error for unsupported format")
		}

		expectedError := "unsupported format: yaml (supported: json, xml, csv, tsv)"
		if err.Error() != expectedError {
			t.Errorf("error message = %v, want %v", err.Error(), expectedError)
		}
	})

	t.Run("csv format", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.csv")
		err = Export(testSBOM, "csv", outputPath)
		if err != nil {
			t.Errorf("Export() failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("CSV file was not created")
		}

		// Verify CSV content includes Filename column
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read CSV file: %v", err)
		}

		contentStr := string(content)
		lines := strings.Split(strings.TrimSpace(contentStr), "\n")

		// Verify header includes Filename
		if len(lines) < 1 {
			t.Fatal("CSV file should have at least a header line")
		}
		header := lines[0]
		expectedHeader := "Name,Source,Version,Location,Filename"
		if header != expectedHeader {
			t.Errorf("CSV header = %q, want %q", header, expectedHeader)
		}

		// Verify data rows include filename values
		if len(lines) < 3 {
			t.Fatal("CSV file should have header + 2 data rows")
		}

		// Check first module row
		firstRow := lines[1]
		if !strings.Contains(firstRow, "main.tf") {
			t.Errorf("First CSV row should contain filename 'main.tf', got: %q", firstRow)
		}

		// Check second module row
		secondRow := lines[2]
		if !strings.Contains(secondRow, "main.tf") {
			t.Errorf("Second CSV row should contain filename 'main.tf', got: %q", secondRow)
		}
	})

	t.Run("tsv format", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "test_export_*")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "sbom.tsv")
		err = Export(testSBOM, "tsv", outputPath)
		if err != nil {
			t.Errorf("Export() failed: %v", err)
		}

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("TSV file was not created")
		}

		// Verify TSV content includes Filename column
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("failed to read TSV file: %v", err)
		}

		contentStr := string(content)
		lines := strings.Split(strings.TrimSpace(contentStr), "\n")

		// Verify header includes Filename
		if len(lines) < 1 {
			t.Fatal("TSV file should have at least a header line")
		}
		header := lines[0]
		expectedHeader := "Name\tSource\tVersion\tLocation\tFilename"
		if header != expectedHeader {
			t.Errorf("TSV header = %q, want %q", header, expectedHeader)
		}

		// Verify data rows include filename values
		if len(lines) < 3 {
			t.Fatal("TSV file should have header + 2 data rows")
		}

		// Check first module row
		firstRow := lines[1]
		if !strings.Contains(firstRow, "main.tf") {
			t.Errorf("First TSV row should contain filename 'main.tf', got: %q", firstRow)
		}

		// Check second module row
		secondRow := lines[2]
		if !strings.Contains(secondRow, "main.tf") {
			t.Errorf("Second TSV row should contain filename 'main.tf', got: %q", secondRow)
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
		err = Export(testSBOM, "xml", outputPath)
		if err != nil {
			t.Fatalf("Export() = %v, want nil", err)
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
		var parsedSBOM sbom.SBOM
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
		err := Export(testSBOM, "json", "/invalid/path/that/does/not/exist/sbom.json")
		if err == nil {
			t.Error("Export() = nil, want error for invalid output path")
		}
		if !strings.Contains(err.Error(), "failed to create output file") {
			t.Errorf("error message = %v, want 'failed to create output file'", err.Error())
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
			{"unknown", "sbom.json"},
			{"", "sbom.json"},
		}

		for _, test := range tests {
			result := GenerateOutputFilename("", test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(\"\", %q) = %q, want %q", test.format, result, test.expected)
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
			{"mysbom", "unknown", "mysbom.json"},
			{"output", "json", "output.json"},
		}

		for _, test := range tests {
			result := GenerateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
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
			{"output.backup", "json", "output.json"},
		}

		for _, test := range tests {
			result := GenerateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
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
		}

		for _, test := range tests {
			result := GenerateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
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
		}

		for _, test := range tests {
			result := GenerateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
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
		}

		for _, test := range tests {
			result := GenerateOutputFilename(test.base, test.format)
			if result != test.expected {
				t.Errorf("GenerateOutputFilename(%q, %q) = %q, want %q", test.base, test.format, result, test.expected)
			}
		}
	})
}
