package export

import (
	"encoding/csv"
	"fmt"
	"io"

	"rodstewart/terraform-sbom/internal/sbom"
)

// exportDelimited exports SBOM as delimited values to the provided writer
func exportDelimited(s *sbom.SBOM, writer io.Writer, separator rune, formatName string) error {
	csvWriter := csv.NewWriter(writer)
	csvWriter.Comma = separator

	// Write header row
	headers := []string{"Name", "Source", "Version", "Location"}
	if err := csvWriter.Write(headers); err != nil {
		return fmt.Errorf("failed to write %s headers: %w", formatName, err)
	}

	// Write data rows
	for _, module := range s.Modules {
		record := []string{module.Name, module.Source, module.Version, module.Location}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("failed to write %s record: %w", formatName, err)
		}
	}

	// Flush and check for errors
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("failed to flush %s writer: %w", formatName, err)
	}

	return nil
}

// CSV exports SBOM as CSV to the provided writer
func CSV(s *sbom.SBOM, writer io.Writer) error {
	return exportDelimited(s, writer, ',', "CSV")
}

// TSV exports SBOM as TSV (tab-separated values) to the provided writer
func TSV(s *sbom.SBOM, writer io.Writer) error {
	return exportDelimited(s, writer, '\t', "TSV")
}
