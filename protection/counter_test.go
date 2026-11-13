package protection

import (
	"testing"
	"time"
)

func TestCounterFixedWindow(t *testing.T) {
	c := NewCounter(8)
	start := time.Unix(1000, 0)
	if n := c.Add("a", start, time.Minute); n != 1 {
		t.Fatalf("n=%d", n)
	}
	if n := c.Add("a", start.Add(30*time.Second), time.Minute); n != 2 {
		t.Fatalf("n=%d", n)
	}
	if n := c.Add("a", start.Add(time.Minute), time.Minute); n != 1 {
		t.Fatalf("new window n=%d", n)
	}
	c.Reset("a")
	if n := c.Add("a", start, time.Minute); n != 1 {
		t.Fatalf("after reset n=%d", n)
	}
}

func TestCounterDoesNotDedupSamePath(t *testing.T) {
	c := NewCounter(8)
	at := time.Unix(1, 0)
	if c.Add("ip|p|/x", at, time.Minute) != 1 || c.Add("ip|p|/x", at.Add(time.Second), time.Minute) != 2 {
		t.Fatal("repeat requests must count")
	}
}
