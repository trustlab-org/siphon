package dedupe

import (
	"testing"
	"time"
)

func TestPruneKeepsOnlyReachableIDs(t *testing.T) {
	s := NewSeen()
	base := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	s.Add("old", base.Add(-2*time.Hour))
	s.Add("new", base)

	s.Prune(base.Add(-time.Hour))

	if s.Has("old") || !s.Has("new") || s.Len() != 1 {
		t.Fatalf("prune kept wrong ids: len=%d", s.Len())
	}
}
