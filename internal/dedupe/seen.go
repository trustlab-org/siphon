package dedupe

import (
	"sync"
	"time"
)

// seen remembers event ids by event time so overlapping poll windows dont reemit them
type Seen struct {
	mu  sync.Mutex
	ids map[string]time.Time
}

func NewSeen() *Seen {
	return &Seen{ids: map[string]time.Time{}}
}

func (s *Seen) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

func (s *Seen) Add(id string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids[id] = at
}

// Prune drops ids older than the earliest time any future window can query
func (s *Seen) Prune(before time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, at := range s.ids {
		if at.Before(before) {
			delete(s.ids, id)
		}
	}
}

func (s *Seen) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ids)
}
