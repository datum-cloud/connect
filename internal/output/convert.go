// Package output provides functions to convert between JSON and YAML.
package output

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// ConvertJSONToYAML takes JSON bytes and returns YAML bytes.
// Returns error if JSON is invalid.
func ConvertJSONToYAML(jsonData []byte) ([]byte, error) {
	// TODO: Phase 2 — implement JSON to YAML conversion
	var data interface{}
	if err := yaml.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParseJSON takes JSON bytes and returns a map[string]interface{}.
func ParseJSON(data []byte) (map[string]interface{}, error) {
	// TODO: Phase 2 — implement JSON parsing
	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}
