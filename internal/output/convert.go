// Package output provides functions to convert between JSON and YAML.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// ConvertJSONToYAML takes JSON bytes and returns YAML bytes.
func ConvertJSONToYAML(jsonData []byte) ([]byte, error) {
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
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// RenderTable takes a JSON array of tunnel objects and renders them
// as a human-readable table to the given writer.
// Expected input: [{"id":"...","label":"...","endpoint":"...","status":"...","enabled":true,"hostnames":["..."]}]
func RenderTable(data []byte, w *tabwriter.Writer) error {
	var tunnels []map[string]interface{}
	if err := json.Unmarshal(data, &tunnels); err != nil {
		return fmt.Errorf("failed to parse tunnel list: %w", err)
	}

	// Header
	fmt.Fprintln(w, "ID\tLABEL\tENDPOINT\tSTATUS\tENABLED\tHOSTNAMES")
	fmt.Fprintln(w, "--\t-----\t--------\t------\t-------\t---------")

	for _, t := range tunnels {
		id := fmt.Sprintf("%v", t["id"])
		label := fmt.Sprintf("%v", t["label"])
		endpoint := fmt.Sprintf("%v", t["endpoint"])
		status := fmt.Sprintf("%v", t["status"])
		enabled := "no"
		if enabledVal, ok := t["enabled"].(bool); ok && enabledVal {
			enabled = "yes"
		}
		hostnames := "\u2014"
		if hnArr, ok := t["hostnames"].([]interface{}); ok && len(hnArr) > 0 {
			hnStrs := make([]string, len(hnArr))
			for i, h := range hnArr {
				hnStrs[i] = fmt.Sprintf("%v", h)
			}
			hostnames = strings.Join(hnStrs, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", id, label, endpoint, status, enabled, hostnames)
	}

	return w.Flush()
}

// RenderSingleJSON takes a single tunnel object and renders it as a
// human-readable table row (single-item table).
func RenderSingleJSON(data []byte, w *tabwriter.Writer) error {
	return RenderTable(data, w)
}
