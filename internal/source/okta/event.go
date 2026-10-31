package okta

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/HelixY2J/collector/internal/envelope"
)

type event struct {
	id        string
	published time.Time
	body      []byte
}

// convert wraps one System Log event in the envelope, keeping Okta's fields as they are.
func convert(e map[string]any, host string, meta envelope.Meta) (event, error) {
	uuid, _ := e["uuid"].(string)
	if uuid == "" {
		return event{}, errors.New("event without uuid")
	}
	ts, _ := e["published"].(string)
	published, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return event{}, fmt.Errorf("event %s published %q: %w", uuid, ts, err)
	}
	if byType := targetsByType(e["target"]); len(byType) > 0 {
		e["target_by_type"] = byType
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return event{}, err
	}
	m := meta
	m.EventID = envelope.ID(host, uuid)
	body, err := envelope.Envelope{Meta: m, Raw: string(raw)}.Marshal()
	if err != nil {
		return event{}, err
	}
	return event{id: m.EventID, published: published, body: body}, nil
}

// targetsByType keys targets by type, first one wins, because json_map rules can't pick list items by a field value.
func targetsByType(v any) map[string]any {
	list, _ := v.([]any)
	out := make(map[string]any, len(list))
	for _, item := range list {
		t, _ := item.(map[string]any)
		typ, _ := t["type"].(string)
		if _, dup := out[typ]; typ != "" && !dup {
			out[typ] = t
		}
	}
	return out
}
