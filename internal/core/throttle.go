package core

import (
	"sync"
	"time"

	"tokencrypt/internal/clock"
)

// throttle counts consecutive wrong passphrases for the whole daemon. After
// max failures every attempt is refused until lockout has passed, measured on
// both clocks (the first to reach it ends the lockout, as for grants). A
// failure after the lockout locks again at once; a success resets the count.
type throttle struct {
	clk     clock.Clock
	max     int
	lockout time.Duration

	mu        sync.Mutex
	fails     int
	locked    bool
	untilWall time.Time
	untilMono time.Duration
}

func newThrottle(clk clock.Clock, max int, lockout time.Duration) *throttle {
	return &throttle{clk: clk, max: max, lockout: lockout}
}

// blocked reports whether attempts are refused now.
func (t *throttle) blocked() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.locked {
		return false
	}
	if !t.clk.Wall().Before(t.untilWall) || t.clk.Mono() >= t.untilMono {
		t.locked = false
		return false
	}
	return true
}

// failure records a wrong passphrase. It returns the count of consecutive
// failures and, when this one started a lockout, the time it ends.
func (t *throttle) failure() (int, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fails++
	if t.fails < t.max {
		return t.fails, time.Time{}
	}
	t.locked = true
	t.untilWall = t.clk.Wall().UTC().Add(t.lockout)
	t.untilMono = t.clk.Mono() + t.lockout
	return t.fails, t.untilWall
}

// success clears the count and any lockout.
func (t *throttle) success() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fails, t.locked = 0, false
}
