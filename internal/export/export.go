package export

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rodstewart/terraform-sbom/internal/sbom"
)

// Export exports an SBOM to a file in the specified format
func Export(s *sbom.SBOM, format string, outputPath string) error {
	// Input validation
	if s == nil {
		return fmt.Errorf("sbom cannot be nil")
	}
	if format == "" {
		return fmt.Errorf("format cannot be empty")
	}
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Export based on format
	switch format {
	case "json":
		return JSON(s, file)
	case "xml":
		return XML(s, file)
	case "csv":
		return CSV(s, file)
	case "tsv":
		return TSV(s, file)
	case "spdx":
		return SPDX(s, file)
	case "cyclonedx":
		return CycloneDX(s, file)
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, xml, csv, tsv, spdx, cyclonedx)", format)
	}
}

// GenerateOutputFilename creates appropriate output filename based on format and base output path
func GenerateOutputFilename(baseOutput, format string) string {
	if baseOutput == "" {
		// Generate default filename based on format
		switch format {
		case "json":
			return "sbom.json"
		case "xml":
			return "sbom.xml"
		case "csv":
			return "sbom.csv"
		case "tsv":
			return "sbom.tsv"
		case "spdx":
			return "sbom.spdx.json"
		case "cyclonedx":
			return "sbom.cyclonedx.json"
		default:
			return "sbom.json"
		}
	}

	// If base output is provided, modify it for the format
	ext := filepath.Ext(baseOutput)
	base := strings.TrimSuffix(baseOutput, ext)

	switch format {
	case "json":
		return base + ".json"
	case "xml":
		return base + ".xml"
	case "csv":
		return base + ".csv"
	case "tsv":
		return base + ".tsv"
	case "spdx":
		return base + ".spdx.json"
	case "cyclonedx":
		return base + ".cyclonedx.json"
	default:
		return base + ".json"
	}
}
