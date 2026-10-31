package okta

import (
	"encoding/json"
	"testing"

	"github.com/HelixY2J/collector/internal/envelope"
)

func sampleEvent() map[string]any {
	return map[string]any{
		"uuid":      "ae4ea33b-d38b-11f1-80c2-e53072160f2d",
		"published": "2026-10-29T11:27:10.350Z",
		"eventType": "policy.evaluate_sign_on",
		"target": []any{
			map[string]any{"type": "AppInstance", "id": "0oa1", "displayName": "Okta Admin Console"},
			map[string]any{"type": "Rule", "id": "r1", "displayName": "first"},
			map[string]any{"type": "Rule", "id": "r2", "displayName": "second"},
			map[string]any{"type": "User", "id": "00u1", "alternateId": "a@example.com"},
		},
	}
}

func TestConvertAddsTargetByType(t *testing.T) {
	meta := envelope.Meta{Org: "lab", Server: "okta", SourceProgram: sourceName}
	ev, err := convert(sampleEvent(), "example.okta.com", meta)
	if err != nil {
		t.Fatal(err)
	}
	if want := envelope.ID("example.okta.com", "ae4ea33b-d38b-11f1-80c2-e53072160f2d"); ev.id != want {
		t.Fatalf("id = %s, want %s", ev.id, want)
	}
	var env envelope.Envelope
	if err := json.Unmarshal(ev.body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Meta.EventID != ev.id || env.Meta.SourceProgram != sourceName || env.Meta.Server != "okta" {
		t.Fatalf("meta = %+v", env.Meta)
	}
	var raw struct {
		Target       []map[string]any          `json:"target"`
		TargetByType map[string]map[string]any `json:"target_by_type"`
	}
	if err := json.Unmarshal([]byte(env.Raw), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Target) != 4 {
		t.Fatalf("original target list must stay intact, got %d items", len(raw.Target))
	}
	if raw.TargetByType["Rule"]["id"] != "r1" || raw.TargetByType["User"]["alternateId"] != "a@example.com" || len(raw.TargetByType) != 3 {
		t.Fatalf("target_by_type = %v", raw.TargetByType)
	}
}

func TestConvertRejectsMalformed(t *testing.T) {
	noUUID := sampleEvent()
	delete(noUUID, "uuid")
	badTime := sampleEvent()
	badTime["published"] = "yesterday"
	for name, e := range map[string]map[string]any{"no uuid": noUUID, "bad published": badTime} {
		if _, err := convert(e, "example.okta.com", envelope.Meta{}); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestConvertWithoutTargets(t *testing.T) {
	e := sampleEvent()
	delete(e, "target")
	ev, err := convert(e, "example.okta.com", envelope.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	_ = json.Unmarshal(ev.body, &env)
	var raw map[string]any
	_ = json.Unmarshal([]byte(env.Raw), &raw)
	if _, ok := raw["target_by_type"]; ok {
		t.Fatal("target_by_type must be absent when the event has no targets")
	}
}
