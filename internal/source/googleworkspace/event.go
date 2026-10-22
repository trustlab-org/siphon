package googleworkspace

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/HelixY2J/collector/internal/envelope"
)

type event struct {
	id   string
	at   time.Time
	body []byte
}

func split(a map[string]any, app string, meta envelope.Meta) ([]event, error) {
	id, _ := a["id"].(map[string]any)
	if id == nil {
		return nil, fmt.Errorf("activity without id")
	}
	ts := text(id["time"])
	at, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, fmt.Errorf("activity time %q: %w", ts, err)
	}
	events, _ := a["events"].([]any)
	out := make([]event, 0, len(events))
	for i, item := range events {
		ev, _ := item.(map[string]any)
		if ev == nil {
			continue
		}
		one := make(map[string]any, len(a)+1)
		for k, v := range a {
			one[k] = v
		}
		one["events"] = []any{ev}
		if params := flatten(ev["parameters"]); len(params) > 0 {
			one["params"] = params
		}
		raw, err := json.Marshal(one)
		if err != nil {
			return nil, err
		}
		m := meta
		m.EventID = envelope.ID(text(id["customerId"]), app, ts, text(id["uniqueQualifier"]), strconv.Itoa(i), text(ev["type"]), text(ev["name"]))
		body, err := envelope.Envelope{Meta: m, Raw: string(raw)}.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, event{id: m.EventID, at: at, body: body})
	}
	return out, nil
}

func flatten(v any) map[string]any {
	list, _ := v.([]any)
	out := make(map[string]any, len(list))
	for _, item := range list {
		p, _ := item.(map[string]any)
		if name := text(p["name"]); name != "" {
			out[name] = paramValue(p)
		}
	}
	return out
}

func paramValue(p map[string]any) any {
	if v, ok := p["value"]; ok {
		return v
	}
	if v, ok := p["multiValue"]; ok {
		return v
	}
	if v, ok := p["intValue"]; ok {
		return integer(v)
	}
	if v, ok := p["multiIntValue"].([]any); ok {
		out := make([]any, len(v))
		for i, n := range v {
			out[i] = integer(n)
		}
		return out
	}
	if v, ok := p["boolValue"]; ok {
		return v
	}
	if v, ok := p["multiBoolValue"]; ok {
		return v
	}
	if m, ok := p["messageValue"].(map[string]any); ok {
		return flatten(m["parameter"])
	}
	if list, ok := p["multiMessageValue"].([]any); ok {
		out := make([]any, 0, len(list))
		for _, item := range list {
			m, _ := item.(map[string]any)
			out = append(out, flatten(m["parameter"]))
		}
		return out
	}
	return false
}

func integer(v any) any {
	if n, err := strconv.ParseInt(text(v), 10, 64); err == nil {
		return n
	}
	return v
}

func text(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}
