package core

import (
	"testing"
	"time"
	"tokencrypt/internal/clock"
)

func TestThrottleReturnsWallOnlyUTCDeadline(t *testing.T) {
	th := newThrottle(clock.Real{}, 1, time.Minute)
	_, until := th.failure()
	if until != until.UTC() {
		t.Fatal("deadline retains a monotonic reading or local zone")
	}
}
