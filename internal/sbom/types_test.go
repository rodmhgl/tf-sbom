package sbom

import (
	"encoding/json"
	"encoding/xml"
	"testing"
)

func TestModuleInfoSerialization(t *testing.T) {
	moduleInfo := ModuleInfo{
		Name:     "test-module",
		Source:   "github.com/example/test-module",
		Version:  "1.0.0",
		Location: "Module call at main.tf:10",
		Filename: "main.tf",
	}

	// Test JSON serialization
	t.Run("JSON serialization", func(t *testing.T) {
		jsonData, err := json.Marshal(moduleInfo)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}

		var unmarshaled ModuleInfo
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if unmarshaled.Name != moduleInfo.Name {
			t.Errorf("Name = %v, want %v", unmarshaled.Name, moduleInfo.Name)
		}
		if unmarshaled.Source != moduleInfo.Source {
			t.Errorf("Source = %v, want %v", unmarshaled.Source, moduleInfo.Source)
		}
		if unmarshaled.Version != moduleInfo.Version {
			t.Errorf("Version = %v, want %v", unmarshaled.Version, moduleInfo.Version)
		}
		if unmarshaled.Location != moduleInfo.Location {
			t.Errorf("Location = %v, want %v", unmarshaled.Location, moduleInfo.Location)
		}
		if unmarshaled.Filename != moduleInfo.Filename {
			t.Errorf("Filename = %v, want %v", unmarshaled.Filename, moduleInfo.Filename)
		}
	})

	// Test XML serialization
	t.Run("XML serialization", func(t *testing.T) {
		xmlData, err := xml.Marshal(moduleInfo)
		if err != nil {
			t.Fatalf("failed to marshal XML: %v", err)
		}

		var unmarshaled ModuleInfo
		err = xml.Unmarshal(xmlData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal XML: %v", err)
		}

		if unmarshaled.Name != moduleInfo.Name {
			t.Errorf("Name = %v, want %v", unmarshaled.Name, moduleInfo.Name)
		}
		if unmarshaled.Source != moduleInfo.Source {
			t.Errorf("Source = %v, want %v", unmarshaled.Source, moduleInfo.Source)
		}
		if unmarshaled.Version != moduleInfo.Version {
			t.Errorf("Version = %v, want %v", unmarshaled.Version, moduleInfo.Version)
		}
		if unmarshaled.Location != moduleInfo.Location {
			t.Errorf("Location = %v, want %v", unmarshaled.Location, moduleInfo.Location)
		}
		if unmarshaled.Filename != moduleInfo.Filename {
			t.Errorf("Filename = %v, want %v", unmarshaled.Filename, moduleInfo.Filename)
		}
	})
}

func TestSBOMSerialization(t *testing.T) {
	testData := SBOM{
		Modules: []ModuleInfo{
			{
				Name:     "module1",
				Source:   "github.com/example/module1",
				Version:  "1.0.0",
				Location: "Module call at main.tf:10",
				Filename: "main.tf",
			},
			{
				Name:     "module2",
				Source:   "github.com/example/module2",
				Version:  "2.0.0",
				Location: "Module call at main.tf:20",
				Filename: "main.tf",
			},
		},
	}

	// Test JSON serialization
	t.Run("JSON serialization", func(t *testing.T) {
		jsonData, err := json.Marshal(testData)
		if err != nil {
			t.Fatalf("failed to marshal JSON: %v", err)
		}

		var unmarshaled SBOM
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}

		if len(unmarshaled.Modules) != len(testData.Modules) {
			t.Errorf("Modules length = %v, want %v", len(unmarshaled.Modules), len(testData.Modules))
		}

		for i, module := range unmarshaled.Modules {
			if module.Name != testData.Modules[i].Name {
				t.Errorf("Module[%d].Name = %v, want %v", i, module.Name, testData.Modules[i].Name)
			}
		}
	})

	// Test XML serialization
	t.Run("XML serialization", func(t *testing.T) {
		xmlData, err := xml.Marshal(testData)
		if err != nil {
			t.Fatalf("failed to marshal XML: %v", err)
		}

		var unmarshaled SBOM
		err = xml.Unmarshal(xmlData, &unmarshaled)
		if err != nil {
			t.Fatalf("failed to unmarshal XML: %v", err)
		}

		if len(unmarshaled.Modules) != len(testData.Modules) {
			t.Errorf("Modules length = %v, want %v", len(unmarshaled.Modules), len(testData.Modules))
		}

		for i, module := range unmarshaled.Modules {
			if module.Name != testData.Modules[i].Name {
				t.Errorf("Module[%d].Name = %v, want %v", i, module.Name, testData.Modules[i].Name)
			}
		}
	})
}
