package googleworkspace

import (
	"bytes"
	"encoding/json"
	"testing"

	reports "google.golang.org/api/admin/reports/v1"
)

// item converts a typed SDK activity into the raw JSON map the collector receives from the API.
func item(t testing.TB, a *reports.Activity) map[string]any {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func items(t testing.TB, acts []*reports.Activity) []map[string]any {
	t.Helper()
	out := make([]map[string]any, len(acts))
	for i, a := range acts {
		out[i] = item(t, a)
	}
	return out
}
