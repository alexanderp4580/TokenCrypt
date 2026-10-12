package clock

import (
	"testing"
	"time"
)

func TestFakeAdvanceMonoLeavesWall(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f := NewFake(start)
	mono := f.Mono()
	f.AdvanceMono(5 * time.Minute)
	if got := f.Mono() - mono; got != 5*time.Minute {
		t.Fatalf("Mono moved by %v, want 5m", got)
	}
	if !f.Wall().Equal(start) {
		t.Fatalf("Wall changed to %v, want %v", f.Wall(), start)
	}
}

func TestFakeSetWallLeavesMono(t *testing.T) {
	f := NewFake(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	f.AdvanceMono(time.Minute)
	mono := f.Mono()
	later := time.Date(2031, 6, 7, 8, 9, 10, 0, time.UTC)
	f.SetWall(later)
	if !f.Wall().Equal(later) {
		t.Fatalf("Wall = %v, want %v", f.Wall(), later)
	}
	if f.Mono() != mono {
		t.Fatalf("Mono = %v, want %v", f.Mono(), mono)
	}
}

func TestFakeAdvanceWallLeavesMono(t *testing.T) {
	start := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f := NewFake(start)
	mono := f.Mono()
	f.AdvanceWall(time.Hour)
	if !f.Wall().Equal(start.Add(time.Hour)) {
		t.Fatalf("Wall = %v, want %v", f.Wall(), start.Add(time.Hour))
	}
	if f.Mono() != mono {
		t.Fatalf("Mono = %v, want %v", f.Mono(), mono)
	}
}

func TestRealMonoNonDecreasing(t *testing.T) {
	var c Clock = Real{}
	prev := c.Mono()
	for i := 0; i < 1000; i++ {
		cur := c.Mono()
		if cur < prev {
			t.Fatalf("Mono went back: %v then %v", prev, cur)
		}
		prev = cur
	}
}
