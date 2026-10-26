package limiter

import "testing"

func TestAllowWithinBudget(t *testing.T) {
	s := New()
	s.Configure("u", 800)
	if !s.Allow("u", 50) {
		t.Fatal("first")
	}
	if s.Allow("u", 100) {
		t.Fatal("should exceed burst")
	}
}

func TestUnlimited(t *testing.T) {
	s := New()
	if !s.Allow("u", 1<<20) {
		t.Fatal("unlimited")
	}
}

func TestWaitSplitsOverBurst(t *testing.T) {
	s := New()
	s.Configure("u", 800)
	if got := s.Wait("u", 250, nil); got != 100 {
		t.Fatalf("first take %d", got)
	}
	stop := make(chan struct{})
	close(stop)
	if got := s.Wait("u", 50, stop); got != 0 {
		t.Fatalf("stopped wait %d", got)
	}
}
