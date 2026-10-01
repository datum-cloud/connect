package output

import (
	"bytes"
	"encoding/json"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"strings"
	"testing"
)

func TestWriteFormats(t *testing.T) {
	for _, format := range []string{"table", "json", "yaml"} {
		t.Run(format, func(t *testing.T) {
			cmd := &cobra.Command{}
			cmd.Flags().String("output", format, "")
			var out bytes.Buffer
			cmd.SetOut(&out)
			if err := Write(cmd, map[string]any{"status": "running", "system": false}, "Connect daemon service is running.\n"); err != nil {
				t.Fatal(err)
			}
			if format == "table" {
				if !strings.HasPrefix(out.String(), "Connect daemon") {
					t.Fatal(out.String())
				}
				return
			}
			var parsed map[string]any
			var err error
			if format == "json" {
				err = json.Unmarshal(out.Bytes(), &parsed)
			} else {
				err = yaml.Unmarshal(out.Bytes(), &parsed)
				if strings.HasPrefix(out.String(), "{") {
					t.Fatal("YAML rendered as JSON")
				}
			}
			if err != nil || parsed["status"] != "running" {
				t.Fatalf("%v: %s", err, out.String())
			}
		})
	}
}
