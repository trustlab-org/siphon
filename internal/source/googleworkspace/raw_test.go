package googleworkspace

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/api/googleapi"

	"github.com/HelixY2J/collector/internal/envelope"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestEventIDUnchangedForRealEvent pins the id of a real event collected before the raw-JSON change, so dedupe stays continuous.
func TestEventIDUnchangedForRealEvent(t *testing.T) {
	a := decode(t, `{"actor":{"callerType":"KEY","key":"NoUserLoggedIn"},"events":[{"name":"CREATE_USER","parameters":[{"name":"USER_EMAIL","value":"admin@trustlabsoc.com"}],"type":"USER_SETTINGS"}],"id":{"applicationName":"admin","customerId":"C025s899b","time":"2026-10-14T08:25:25.734Z","uniqueQualifier":"875091181611218308"},"ipAddress":"103.21.125.84","kind":"admin#reports#activity","networkInfo":{"ipAsn":[132423],"regionCode":"IN","subdivisionCode":"IN-MH"}}`)
	evs, err := split(a, "admin", envelope.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0].id != "6f9f082e0d29c29edfbef8b420355ab8" {
		t.Fatalf("event id changed: %+v", evs)
	}
}

func TestDeeplyNestedParametersSurvive(t *testing.T) {
	a := decode(t, `{"id":{"applicationName":"gmail","customerId":"C1","time":"2026-10-21T09:00:00Z","uniqueQualifier":"-42"},
	 "events":[{"type":"email","name":"delivery","parameters":[
	  {"name":"event_info","messageValue":{"parameter":[{"name":"mail_event_type","intValue":"15"},{"name":"success","boolValue":true}]}},
	  {"name":"message_info","messageValue":{"parameter":[
	    {"name":"subject","value":"Verify your account"},
	    {"name":"source","messageValue":{"parameter":[{"name":"address","value":"it-support@evil.example"}]}},
	    {"name":"destination","multiMessageValue":[{"parameter":[{"name":"address","value":"user1@trustlabsoc.com"}]},{"parameter":[{"name":"address","value":"user2@trustlabsoc.com"}]}]},
	    {"name":"is_spam"}]}}]}]}`)
	evs, err := split(a, "gmail", envelope.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	var env envelope.Envelope
	_ = json.Unmarshal(evs[0].body, &env)
	var doc struct {
		Params struct {
			EventInfo struct {
				MailEventType int64 `json:"mail_event_type"`
				Success       bool  `json:"success"`
			} `json:"event_info"`
			MessageInfo struct {
				Subject     string                     `json:"subject"`
				Source      struct{ Address string }   `json:"source"`
				Destination []struct{ Address string } `json:"destination"`
				IsSpam      bool                       `json:"is_spam"`
			} `json:"message_info"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(env.Raw), &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Params
	if p.EventInfo.MailEventType != 15 || !p.EventInfo.Success || p.MessageInfo.Subject != "Verify your account" ||
		p.MessageInfo.Source.Address != "it-support@evil.example" || len(p.MessageInfo.Destination) != 2 ||
		p.MessageInfo.Destination[1].Address != "user2@trustlabsoc.com" || p.MessageInfo.IsSpam {
		t.Fatalf("nested params lost: %+v", p)
	}
}

func TestUnavailableClassification(t *testing.T) {
	cases := []struct {
		err  *googleapi.Error
		want bool
	}{
		{&googleapi.Error{Code: http.StatusBadRequest}, true},
		{&googleapi.Error{Code: http.StatusNotFound}, true},
		{&googleapi.Error{Code: http.StatusForbidden}, true},
		{&googleapi.Error{Code: http.StatusForbidden, Errors: []googleapi.ErrorItem{{Reason: "rateLimitExceeded"}}}, false},
		{&googleapi.Error{Code: http.StatusTooManyRequests}, false},
		{&googleapi.Error{Code: http.StatusUnauthorized}, false},
	}
	for _, c := range cases {
		if got := unavailable(c.err); got != c.want {
			t.Errorf("unavailable(%d %v) = %v, want %v", c.err.Code, c.err.Errors, got, c.want)
		}
	}
}
