package export

import (
	"encoding/xml"
	"fmt"
	"io"

	"rodstewart/terraform-sbom/internal/sbom"
)

// XML exports SBOM as XML to the provided writer
func XML(s *sbom.SBOM, writer io.Writer) error {
	// Write XML header first
	if _, err := writer.Write([]byte(xml.Header)); err != nil {
		return fmt.Errorf("failed to write XML header: %w", err)
	}

	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ") // Pretty print with 2-space indentation

	if err := encoder.Encode(s); err != nil {
		return fmt.Errorf("failed to encode SBOM as XML: %w", err)
	}

	return nil
}
