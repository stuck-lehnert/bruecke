package bruecke

import (
	"encoding/json"
	"fmt"
	"os"
)

// writeJSONFile replaces a store only after the complete JSON document is written.
// Callers must serialize writes to the same path and create its parent directory.
func writeJSONFile(path, label string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", label, err)
	}
	data = append(data, '\n')

	temporaryPath := path + ".tmp"
	defer os.Remove(temporaryPath)
	if err := os.WriteFile(temporaryPath, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", label, err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace %s: %w", label, err)
	}
	return nil
}
