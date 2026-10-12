package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"tokencrypt/internal/clock"
)

// Retaining time.Time's monotonic reading makes the wall expiry branch use
// that reading too, so a suspended monotonic clock can bypass idle expiry.
func TestSessionStoresWallTimeWithoutMonotonicReading(t *testing.T) {
	wall := time.Now()
	if wall == wall.Round(0) {
		t.Fatal("test requires a monotonic-bearing wall timestamp")
	}
	for _, auth := range []bool{false, true} {
		name := "preauth"
		cookieName := preauthCookie
		if auth {
			name = "authenticated"
			cookieName = sessionCookie
		}
		t.Run(name, func(t *testing.T) {
			clk := clock.NewFake(wall)
			store := &sessionStore{items: map[string]session{}, clk: clk, timeout: time.Minute}
			x, err := store.create(auth)
			if err != nil {
				t.Fatal(err)
			}
			if x.wall != wall.Round(0) {
				t.Error("creation kept a monotonic reading in the wall timestamp")
			}
			refreshedWall := wall.Add(time.Second)
			clk.SetWall(refreshedWall)
			r := httptest.NewRequest("GET", "http://crypt.local/", nil)
			r.AddCookie(&http.Cookie{Name: cookieName, Value: x.id})
			refreshed, ok := store.get(r, auth)
			if !ok {
				t.Fatal("session unexpectedly expired before refresh")
			}
			if refreshed.wall != refreshedWall.Round(0) || store.items[x.id].wall != refreshedWall.Round(0) {
				t.Error("refresh kept a monotonic reading in the wall timestamp")
			}
		})
	}
}
