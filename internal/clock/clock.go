// Package clock separates wall time from monotonic time so tests can move
// each one independently.
package clock

import (
	"sync"
	"time"
)

// Clock reports wall time and a monotonic duration since an arbitrary start.
type Clock interface {
	Wall() time.Time
	Mono() time.Duration
}

// Real reads the system clocks.
type Real struct{}

var processStart = time.Now()

// Wall returns the current system time.
func (Real) Wall() time.Time { return time.Now() }

// Mono returns the monotonic time elapsed since the process started.
func (Real) Mono() time.Duration { return time.Since(processStart) }

// Fake is a Clock whose wall and monotonic readings only move when told to.
type Fake struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

// NewFake returns a Fake with the given wall time and Mono() of zero.
func NewFake(wall time.Time) *Fake { return &Fake{wall: wall} }

// Wall returns the fake wall time.
func (f *Fake) Wall() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wall
}

// Mono returns the fake monotonic time.
func (f *Fake) Mono() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mono
}

// SetWall sets the wall time; Mono is unchanged.
func (f *Fake) SetWall(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = t
}

// AdvanceWall moves the wall time by d; Mono is unchanged.
func (f *Fake) AdvanceWall(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.wall = f.wall.Add(d)
}

// AdvanceMono moves the monotonic time by d; Wall is unchanged.
func (f *Fake) AdvanceMono(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mono += d
}
