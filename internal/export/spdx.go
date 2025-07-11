package export

import (
	"fmt"
	"io"
	"time"

	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"rodstewart/terraform-sbom/internal/sbom"
)

// ConvertToSPDX converts our SBOM to an SPDX document
func ConvertToSPDX(s *sbom.SBOM) *v2_3.Document {
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
		Packages: make([]*v2_3.Package, len(s.Modules)),
	}

	// Convert each module to an SPDX package
	for i, module := range s.Modules {
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

// SPDX exports an SBOM to a writer in SPDX JSON format
func SPDX(s *sbom.SBOM, writer io.Writer) error {
	spdxDoc := ConvertToSPDX(s)
	return spdxjson.Write(spdxDoc, writer)
}
