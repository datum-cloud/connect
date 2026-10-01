// Package output converts daemon responses to the requested output format.
package output

import (
	"encoding/json"
	"gopkg.in/yaml.v3"
)

func ConvertJSONToYAML(data []byte) ([]byte, error) {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return yaml.Marshal(value)
}
