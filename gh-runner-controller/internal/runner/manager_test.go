package runner

import "testing"

func TestManager(t *testing.T) {
	m := NewManager()

	if m.Count() != 0 {
		t.Errorf("expected 0 runners, got %d", m.Count())
	}

	m.Add()
	if m.Count() != 1 {
		t.Errorf("expected 1 runner, got %d", m.Count())
	}

	m.Remove()
	if m.Count() != 0 {
		t.Errorf("expected 0 runners, got %d", m.Count())
	}
}
