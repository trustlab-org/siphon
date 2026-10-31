package googleworkspace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HelixY2J/collector/internal/envelope"
	"github.com/HelixY2J/collector/internal/fakegws"
)

// TestWriteEngineSamples regenerates engine golden inputs; it only runs when ENGINE_SAMPLES_DIR is set.
func TestWriteEngineSamples(t *testing.T) {
	dir := os.Getenv("ENGINE_SAMPLES_DIR")
	if dir == "" {
		t.Skip("ENGINE_SAMPLES_DIR not set")
	}
	synth := fakegws.NewSynth(7, "example.ac.in", 20)
	base := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	for _, app := range []string{"login", "token", "drive", "admin", "user_accounts"} {
		name := "google_workspace_" + app
		var lines []byte
		for i := range 6 {
			evs, err := split(item(t, synth.Activity(app, base.Add(time.Duration(i)*time.Minute))), app, envelope.Meta{SourceProgram: name})
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range evs {
				var env envelope.Envelope
				if err := json.Unmarshal(e.body, &env); err != nil {
					t.Fatal(err)
				}
				lines = append(lines, env.Raw...)
				lines = append(lines, '\n')
			}
		}
		out := filepath.Join(dir, name)
		if err := os.MkdirAll(out, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, "input.log"), lines, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
