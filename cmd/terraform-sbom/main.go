package main

import (
	"fmt"
	"os"
	"strings"

	"rodstewart/terraform-sbom/internal/cli"
	"rodstewart/terraform-sbom/internal/export"
	"rodstewart/terraform-sbom/internal/sbom"
)

func main() {
	config, err := cli.ParseFlags()
	if err != nil {
		os.Exit(1)
	}

	if config.Verbose {
		fmt.Printf("Generating SBOM for Terraform configuration in: %s\n", config.ConfigPath)
		fmt.Printf("Output formats: %s\n", strings.Join(config.Format, ", "))
	}

	s, err := sbom.Generate(config.ConfigPath, config.Recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(s.Modules) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: No module calls found in %s\n", config.ConfigPath)
	} else {
		fmt.Printf("Found %d module(s)\n", len(s.Modules))
	}

	// Export SBOM in all requested formats
	for _, formatType := range config.Format {
		outputFile := export.GenerateOutputFilename(config.Output, formatType)
		if config.Verbose {
			fmt.Printf("Exporting %s format to: %s\n", formatType, outputFile)
		}

		if err := export.Export(s, formatType, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error exporting %s format: %v\n", formatType, err)
			os.Exit(1)
		}

		fmt.Printf("SBOM successfully exported to %s (format: %s)\n", outputFile, formatType)
	}
}
