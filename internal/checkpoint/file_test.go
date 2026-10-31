package checkpoint

import (
	"context"
	"path/filepath"
	"testing"
)

func TestFileStoreSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nested", "cp.json")
	s, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx, "a"); v != nil {
		t.Fatalf("want nil for unset key, got %q", v)
	}
	if err := s.Set(ctx, "a", []byte("2026-09-30T10:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, "b", []byte("x")); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := reopened.Get(ctx, "a"); string(v) != "2026-09-30T10:00:00Z" {
		t.Fatalf("got %q after reopen", v)
	}
	if v, _ := reopened.Get(ctx, "b"); string(v) != "x" {
		t.Fatalf("got %q after reopen", v)
	}
}
