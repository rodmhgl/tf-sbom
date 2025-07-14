package sbom

import (
	"encoding/xml"
)

// ModuleInfo represents information about a Terraform module
type ModuleInfo struct {
	Name     string `json:"name" xml:"name"`
	Source   string `json:"source" xml:"source"`
	Version  string `json:"version" xml:"version"`
	Location string `json:"location" xml:"location"`
	Filename string `json:"filename" xml:"filename"`
}

// SBOM represents a Software Bill of Materials for Terraform configurations
type SBOM struct {
	XMLName   xml.Name     `json:"-" xml:"SBOM"`
	Version   string       `json:"version" xml:"version,attr"`
	Generated string       `json:"generated" xml:"generated,attr"`
	Tool      string       `json:"tool" xml:"tool,attr"`
	Modules   []ModuleInfo `json:"modules" xml:"Modules>Module"`
}
