package main

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/hashicorp/terraform-config-inspect/tfconfig"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// ModuleInfo represents information about a Terraform module
type ModuleInfo struct {
	Name     string `json:"name" xml:"name"`
	Source   string `json:"source" xml:"source"`
	Version  string `json:"version" xml:"version"`
	Location string `json:"location" xml:"location"`
}

// SBOM represents a Software Bill of Materials for Terraform configurations
type SBOM struct {
	XMLName   xml.Name     `json:"-" xml:"SBOM"`
	Version   string       `json:"version" xml:"version,attr"`
	Generated string       `json:"generated" xml:"generated,attr"`
	Tool      string       `json:"tool" xml:"tool,attr"`
	Modules   []ModuleInfo `json:"modules" xml:"Modules>Module"`
}

// hasTerraformFiles checks if a directory contains any .tf files
func hasTerraformFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".tf") {
			return true
		}
	}
	return false
}

// validateTerraformDirectory checks if a directory exists and is suitable for Terraform module loading
func validateTerraformDirectory(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("path must be a directory containing Terraform files: %s", path)
	}

	return nil
}

// findTerraformModules recursively searches for directories containing Terraform files
func findTerraformModules(root string, recursive bool) ([]string, error) {
	if !recursive {
		// Non-recursive mode: return the root directory if it has .tf files, otherwise return an empty slice
		if hasTerraformFiles(root) {
			return []string{root}, nil
		}
		return []string{}, nil // Return an empty slice if no .tf files are found
	}

	var modules []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Log the error and continue walking instead of aborting
			fmt.Fprintf(os.Stderr, "Warning: skipping %s due to error: %v\n", path, err)
			return nil
		}

		// Skip hidden directories (e.g., .terraform, .git)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != root {
			return filepath.SkipDir
		}

		if d.IsDir() && hasTerraformFiles(path) {
			modules = append(modules, path)
		}
		return nil
	})
	return modules, err
}

// generateSBOM generates a Software Bill of Materials for a Terraform configuration
func generateSBOM(configPath string, recursive bool) (*SBOM, error) {
	// Validate the configuration path exists
	if err := validateTerraformDirectory(configPath); err != nil {
		return nil, err
	}

	// Clean the path to ensure it's absolute
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Find all Terraform module directories
	moduleDirs, err := findTerraformModules(absPath, recursive)
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
			}
			sbom.Modules = append(sbom.Modules, moduleInfo)
		}
	}

	return sbom, nil
}

// convertToSPDX converts our SBOM to an SPDX document
func convertToSPDX(sbom *SBOM) *v2_3.Document {
	// Create the SPDX document
	doc := &v2_3.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "SPDXRef-DOCUMENT",
		DocumentName:      "Terraform Configuration SBOM",
		DocumentNamespace: fmt.Sprintf("https://terraform-sbom.local/%s", time.Now().Format("2006-01-02T15:04:05Z")),
		CreationInfo: &v2_3.CreationInfo{
			Created: time.Now().Format(time.RFC3339),
			Creators: []common.Creator{
				{Creator: "Tool: terraform-sbom"},
			},
		},
		Packages: make([]*v2_3.Package, len(sbom.Modules)),
	}

	// Convert each module to an SPDX package
	for i, module := range sbom.Modules {
		pkg := &v2_3.Package{
			PackageName:             module.Name,
			PackageSPDXIdentifier:   common.ElementID(fmt.Sprintf("SPDXRef-Package-%d", i)),
			PackageDownloadLocation: module.Source,
			PackageCopyrightText:    "NOASSERTION",
		}

		// Set version if available
		if module.Version != "" {
			pkg.PackageVersion = module.Version
		} else {
			pkg.PackageVersion = "NOASSERTION"
		}

		doc.Packages[i] = pkg
	}

	return doc
}

// exportSPDX exports an SBOM to a writer in SPDX JSON format
func exportSPDX(sbom *SBOM, writer io.Writer) error {
	spdxDoc := convertToSPDX(sbom)
	return spdxjson.Write(spdxDoc, writer)
}

// convertToCycloneDX converts our SBOM to a CycloneDX BOM
func convertToCycloneDX(sbom *SBOM) *cyclonedx.BOM {
	// Create the CycloneDX BOM
	bom := cyclonedx.NewBOM()
	bom.BOMFormat = "CycloneDX"
	bom.SpecVersion = cyclonedx.SpecVersion1_6
	bom.Version = 1

	// Set metadata
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Tools: &[]cyclonedx.Tool{
				{
					Name:    "terraform-sbom",
					Version: "1.0.0",
				},
			},
		},
	}

	// Convert each module to a CycloneDX component
	components := make([]cyclonedx.Component, len(sbom.Modules))
	for i, module := range sbom.Modules {
		component := cyclonedx.Component{
			Type: cyclonedx.ComponentTypeLibrary,
			Name: module.Name,
		}

		// Set version if available
		if module.Version != "" {
			component.Version = module.Version
		}

		// Extract group from source if it's a registry module
		if len(module.Source) > 0 {
			// For registry modules like "terraform-aws-modules/vpc/aws"
			// Use the first part as the group
			parts := strings.Split(module.Source, "/")
			if len(parts) > 0 {
				component.Group = parts[0]
			}
		}

		components[i] = component
	}

	bom.Components = &components
	return bom
}

// exportCycloneDX exports an SBOM to a writer in CycloneDX JSON format
func exportCycloneDX(sbom *SBOM, writer io.Writer) error {
	cycloneDXBOM := convertToCycloneDX(sbom)
	encoder := cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON)
	return encoder.Encode(cycloneDXBOM)
}

// exportSBOM exports an SBOM to a file in the specified format
func exportSBOM(sbom *SBOM, format string, outputPath string) error {
	// Input validation
	if sbom == nil {
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
		return exportJSON(sbom, file)
	case "xml":
		return exportXML(sbom, file)
	case "csv":
		return exportCSV(sbom, file)
	case "tsv":
		return exportTSV(sbom, file)
	case "spdx":
		return exportSPDX(sbom, file)
	case "cyclonedx":
		return exportCycloneDX(sbom, file)
	default:
		return fmt.Errorf("unsupported format: %s (supported: json, xml, csv, tsv, spdx, cyclonedx)", format)
	}
}

// exportJSON exports SBOM as JSON to the provided writer
func exportJSON(sbom *SBOM, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ") // Pretty print with 2-space indentation

	if err := encoder.Encode(sbom); err != nil {
		return fmt.Errorf("failed to encode SBOM as JSON: %w", err)
	}

	return nil
}

// exportXML exports SBOM as XML to the provided writer
func exportXML(sbom *SBOM, writer io.Writer) error {
	// Write XML header first
	if _, err := writer.Write([]byte(xml.Header)); err != nil {
		return fmt.Errorf("failed to write XML header: %w", err)
	}

	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ") // Pretty print with 2-space indentation

	if err := encoder.Encode(sbom); err != nil {
		return fmt.Errorf("failed to encode SBOM as XML: %w", err)
	}

	return nil
}

// exportCSV exports SBOM as CSV to the provided writer
func exportCSV(sbom *SBOM, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write header row
	headers := []string{"Name", "Source", "Version", "Location"}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV headers: %w", err)
	}

	// Write data rows
	for _, module := range sbom.Modules {
		record := []string{module.Name, module.Source, module.Version, module.Location}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}

// exportTSV exports SBOM as TSV (tab-separated values) to the provided writer
func exportTSV(sbom *SBOM, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	csvWriter.Comma = '\t' // Use tab separator for TSV
	defer csvWriter.Flush()

	// Write header row
	headers := []string{"Name", "Source", "Version", "Location"}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write TSV headers: %w", err)
	}

	// Write data rows
	for _, module := range sbom.Modules {
		record := []string{module.Name, module.Source, module.Version, module.Location}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write TSV record: %w", err)
		}
	}

	return nil
}

// generateOutputFilename creates appropriate output filename based on format and base output path
func generateOutputFilename(baseOutput, format string) string {
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

func main() {
	var (
		format    = flag.String("f", "json", "Output format(s) - comma-separated (json, xml, csv, tsv, spdx, cyclonedx)")
		output    = flag.String("o", "", "Output file path base (extensions added automatically)")
		verbose   = flag.Bool("v", false, "Verbose output")
		recursive = flag.Bool("r", false, "Recursively scan for Terraform modules")
	)
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <terraform-directory>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nArguments:\n")
		fmt.Fprintf(os.Stderr, "  terraform-directory: Directory containing Terraform configuration files\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -f json -o sbom.json ./terraform\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -r -f spdx -o sbom ./project    # Recursively scan all modules\n", os.Args[0])
		os.Exit(1)
	}

	configPath := flag.Arg(0)

	// Parse comma-separated formats
	formats := strings.Split(*format, ",")
	for i, fmt := range formats {
		formats[i] = strings.TrimSpace(fmt)
	}

	if *verbose {
		fmt.Printf("Generating SBOM for Terraform configuration in: %s\n", configPath)
		fmt.Printf("Output formats: %s\n", strings.Join(formats, ", "))
	}

	sbom, err := generateSBOM(configPath, *recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(sbom.Modules) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: No module calls found in %s\n", configPath)
	} else {
		fmt.Printf("Found %d module(s)\n", len(sbom.Modules))
	}

	// Export SBOM in all requested formats
	for _, formatType := range formats {
		outputFile := generateOutputFilename(*output, formatType)
		if *verbose {
			fmt.Printf("Exporting %s format to: %s\n", formatType, outputFile)
		}

		if err := exportSBOM(sbom, formatType, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting %s format: %v\n", formatType, err)
			os.Exit(1)
		}

		fmt.Printf("SBOM successfully exported to %s (format: %s)\n", outputFile, formatType)
	}
}
