package export

import (
	"io"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"rodstewart/terraform-sbom/internal/sbom"
)

// ConvertToCycloneDX converts our SBOM to a CycloneDX BOM
func ConvertToCycloneDX(s *sbom.SBOM) *cyclonedx.BOM {
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
	components := make([]cyclonedx.Component, len(s.Modules))
	for i, module := range s.Modules {
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

// CycloneDX exports an SBOM to a writer in CycloneDX JSON format
func CycloneDX(s *sbom.SBOM, writer io.Writer) error {
	cycloneDXBOM := ConvertToCycloneDX(s)
	encoder := cyclonedx.NewBOMEncoder(writer, cyclonedx.BOMFileFormatJSON)
	return encoder.Encode(cycloneDXBOM)
}
