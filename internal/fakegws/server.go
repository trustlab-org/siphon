package fakegws

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	reports "google.golang.org/api/admin/reports/v1"
)

type Server struct {
	mu        sync.Mutex
	apps      map[string][]*reports.Activity
	throttle  float64
	rng       *rand.Rand
	requests  int
	throttled int
}

type Stats struct {
	Requests  int            `json:"requests"`
	Throttled int            `json:"throttled"`
	Visible   map[string]int `json:"visible"`
}

func New(seed int64, throttle float64) *Server {
	return &Server{apps: map[string][]*reports.Activity{}, throttle: throttle, rng: rand.New(rand.NewSource(seed))}
}

func (s *Server) Add(a *reports.Activity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apps[a.Id.ApplicationName] = append(s.apps[a.Id.ApplicationName], a)
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Stats{Requests: s.requests, Throttled: s.throttled, Visible: map[string]int{}}
	for app, items := range s.apps {
		st.Visible[app] = len(items)
	}
	return st
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/stats" {
		writeJSON(w, http.StatusOK, s.Stats())
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 8 || parts[0] != "admin" || parts[3] != "activity" || parts[6] != "applications" {
		writeError(w, http.StatusNotFound, "notFound", "unknown path "+r.URL.Path)
		return
	}
	app := parts[7]
	q := r.URL.Query()
	start, err1 := time.Parse(time.RFC3339Nano, q.Get("startTime"))
	end, err2 := time.Parse(time.RFC3339Nano, q.Get("endTime"))
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "invalid", "startTime and endTime are required")
		return
	}
	limit, _ := strconv.Atoi(q.Get("maxResults"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}

	s.mu.Lock()
	s.requests++
	if s.rng.Float64() < s.throttle {
		s.throttled++
		s.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "rateLimitExceeded", "Quota exceeded")
		return
	}
	var matched []*reports.Activity
	for _, a := range s.apps[app] {
		t, _ := time.Parse(time.RFC3339Nano, a.Id.Time)
		if !t.Before(start) && t.Before(end) {
			matched = append(matched, a)
		}
	}
	s.mu.Unlock()

	sort.Slice(matched, func(i, j int) bool { return newer(matched[i], matched[j]) })
	if tok := q.Get("pageToken"); tok != "" {
		after, err := decodeToken(tok)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid", "bad pageToken")
			return
		}
		i := sort.Search(len(matched), func(i int) bool { return newer(after, matched[i]) })
		matched = matched[i:]
	}
	res := reports.Activities{Kind: "admin#reports#activities"}
	if len(matched) > limit {
		res.NextPageToken = encodeToken(matched[limit-1])
		matched = matched[:limit]
	}
	res.Items = matched
	writeJSON(w, http.StatusOK, res)
}

// newer orders activities newest first, as Google does, with a stable tiebreak.
func newer(a, b *reports.Activity) bool {
	ta, _ := time.Parse(time.RFC3339Nano, a.Id.Time)
	tb, _ := time.Parse(time.RFC3339Nano, b.Id.Time)
	if !ta.Equal(tb) {
		return ta.After(tb)
	}
	return a.Id.UniqueQualifier > b.Id.UniqueQualifier
}

func encodeToken(a *reports.Activity) string {
	return base64.RawURLEncoding.EncodeToString([]byte(a.Id.Time + "|" + strconv.FormatInt(a.Id.UniqueQualifier, 10)))
}

func decodeToken(tok string) (*reports.Activity, error) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, err
	}
	t, q, ok := strings.Cut(string(raw), "|")
	if !ok {
		return nil, fmt.Errorf("malformed token")
	}
	uq, err := strconv.ParseInt(q, 10, 64)
	if err != nil {
		return nil, err
	}
	return &reports.Activity{Id: &reports.ActivityId{Time: t, UniqueQualifier: uq}}, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, reason, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]any{
		"code": code, "message": msg, "errors": []map[string]string{{"reason": reason, "message": msg}},
	}})
}
