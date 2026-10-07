package output

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/cobra"
)

// Write renders a native operation consistently with daemon-backed commands.
func Write(cmd *cobra.Command, value any, human string) error {
	format, _ := cmd.Flags().GetString("output")
	if format == "" || format == "table" {
		_, err := fmt.Fprint(cmd.OutOrStdout(), human)
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	switch format {
	case "json":
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
	case "yaml":
		data, err = ConvertJSONToYAML(data)
		if err == nil {
			_, err = cmd.OutOrStdout().Write(data)
		}
	default:
		err = fmt.Errorf("unsupported output format %q (use table, json, or yaml)", format)
	}
	return err
}
