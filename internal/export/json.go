package export

import (
	"encoding/json"
	"fmt"
	"io"

	"rodstewart/terraform-sbom/internal/sbom"
)

// JSON exports SBOM as JSON to the provided writer
func JSON(s *sbom.SBOM, writer io.Writer) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ") // Pretty print with 2-space indentation

	if err := encoder.Encode(s); err != nil {
		return fmt.Errorf("failed to encode SBOM as JSON: %w", err)
	}

	return nil
}
