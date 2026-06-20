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

// RenderTable takes a JSON array of tunnel/connector objects and renders them
// as a human-readable table to the given writer.
// Expected input: [{"type":"tunnel","id":"...","label":"...","endpoint":"...","status":"...","enabled":true,"hostnames":["..."],"connector":"ok|stale"}]
// Orphaned connectors have type "orphaned_connector" and are rendered in a
// separate section below the tunnel rows.
func RenderTable(data []byte, w *tabwriter.Writer) error {
	var items []map[string]interface{}
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("failed to parse tunnel list: %w", err)
	}

	var tunnels []map[string]interface{}
	var orphans []map[string]interface{}
	for _, item := range items {
		if fmt.Sprintf("%v", item["type"]) == "orphaned_connector" {
			orphans = append(orphans, item)
		} else {
			tunnels = append(tunnels, item)
		}
	}

	// Header
	fmt.Fprintln(w, "ID\tLABEL\tENDPOINT\tSTATUS\tENABLED\tCONNECTOR\tHOSTNAMES")
	fmt.Fprintln(w, "--\t-----\t--------\t------\t-------\t---------\t---------")

	for _, t := range tunnels {
		id := fmt.Sprintf("%v", t["id"])
		label := fmt.Sprintf("%v", t["label"])
		endpoint := fmt.Sprintf("%v", t["endpoint"])
		status := fmt.Sprintf("%v", t["status"])
		enabled := "no"
		if enabledVal, ok := t["enabled"].(bool); ok && enabledVal {
			enabled = "yes"
		}
		connector := fmt.Sprintf("%v", t["connector"])
		hostnames := "\u2014"
		if hnArr, ok := t["hostnames"].([]interface{}); ok && len(hnArr) > 0 {
			hnStrs := make([]string, len(hnArr))
			for i, h := range hnArr {
				hnStrs[i] = fmt.Sprintf("%v", h)
			}
			hostnames = strings.Join(hnStrs, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, label, endpoint, status, enabled, connector, hostnames)
	}

	if len(orphans) > 0 {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "ORPHANED CONNECTORS (no tunnel — safe to delete)")
		fmt.Fprintln(w, "NAME\tSTATUS")
		fmt.Fprintln(w, "----\t------")
		for _, o := range orphans {
			name := fmt.Sprintf("%v", o["id"])
			connector := fmt.Sprintf("%v", o["connector"])
			fmt.Fprintf(w, "%s\t%s\n", name, connector)
		}
	}

	return w.Flush()
}

// RenderSingleJSON takes a single tunnel object and renders it as a
// human-readable table row (single-item table).
func RenderSingleJSON(data []byte, w *tabwriter.Writer) error {
	return RenderTable(data, w)
}
