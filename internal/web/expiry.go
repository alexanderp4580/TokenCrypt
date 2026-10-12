package web

import (
	"fmt"
	"net/http"
	"time"

	"tokencrypt/internal/vault"
)

type expiryChoice struct{ Value, Label string }

var expiryChoices = []expiryChoice{
	{"never", "Never"}, {"1d", "1 day"}, {"3d", "3 days"}, {"1w", "1 week"}, {"2w", "2 weeks"},
	{"1m", "1 month"}, {"3m", "3 months"}, {"6m", "6 months"}, {"1y", "1 year"}, {"2y", "2 years"}, {"custom", "Custom date"},
}

func resolveExpiry(choice, date string, today time.Time) (string, error) {
	if choice == "" || choice == "never" {
		return "", nil
	}
	if choice == "custom" {
		if date == "" || !vault.ValidExpiry(date) {
			return "", vault.ErrBadExpiry
		}
		return date, nil
	}
	y, m, d := today.Date()
	base := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	days := map[string]int{"1d": 1, "3d": 3, "1w": 7, "2w": 14}
	months := map[string]int{"1m": 1, "3m": 3, "6m": 6, "1y": 12, "2y": 24}
	var end time.Time
	if n, ok := days[choice]; ok {
		end = base.AddDate(0, 0, n)
	} else if n, ok := months[choice]; ok {
		first := time.Date(y, m+time.Month(n), 1, 0, 0, 0, 0, time.UTC)
		last := first.AddDate(0, 1, -1).Day()
		if d > last {
			d = last
		}
		end = first.AddDate(0, 0, d-1)
	} else {
		return "", vault.ErrBadExpiry
	}
	out := end.Format("2006-01-02")
	if !vault.ValidExpiry(out) {
		return "", vault.ErrBadExpiry
	}
	return out, nil
}

func expiryRemaining(date string, now time.Time) string {
	if date == "" {
		return "Never"
	}
	end, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "Invalid date"
	}
	y, m, d := now.Date()
	today := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	days := int((end.Unix() - today.Unix()) / 86400)
	if end.Before(today) {
		return "Expired"
	}
	if days == 0 {
		return "Expires today"
	}
	if days == 1 {
		return "1 day left"
	}
	return fmt.Sprintf("%d days left", days)
}

func expiryDateLabel(date string) string {
	if date == "" {
		return "Never"
	}
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return "Invalid date"
	}
	return t.Format("2 Jan 2006")
}

func (s *server) formExpiry(r *http.Request) (string, error) {
	if r.URL.Path == "/secrets/expiry" {
		choices := r.PostForm["expiry_choice"]
		if len(choices) != 1 || choices[0] == "" {
			return "", vault.ErrBadExpiry
		}
	}
	date := r.PostForm.Get("expires_on")
	if !vault.ValidExpiry(date) {
		return "", vault.ErrBadExpiry
	}
	today := s.cfg.Clock.Wall()
	if local := r.PostForm.Get("expiry_today"); local != "" {
		if !vault.ValidExpiry(local) {
			return "", vault.ErrBadExpiry
		}
		today, _ = time.Parse("2006-01-02", local)
	}
	return resolveExpiry(r.PostForm.Get("expiry_choice"), r.PostForm.Get("expires_on"), today)
}

// secretError retains expiry input while rendering no submitted credentials.
func (s *server) secretError(w http.ResponseWriter, r *http.Request, x session, err error) {
	if r.URL.Path != "/secrets/create" && r.URL.Path != "/secrets/expiry" {
		s.result(w, r, x, "secrets", err)
		return
	}
	status, message := operationError(err)
	d := pageData{Title: "Secrets", Section: "secrets", CSRF: x.csrf, Authenticated: true, State: s.svc.Status(), Error: message, ExpiryChoice: r.PostForm.Get("expiry_choice"), ExpiryDate: r.PostForm.Get("expires_on")}
	if d.ExpiryChoice == "" {
		d.ExpiryChoice = "never"
	}
	if r.URL.Path == "/secrets/expiry" {
		for _, m := range d.State.Secrets {
			if m.Name == r.PostForm.Get("name") && !m.Corrupt {
				d.Title, d.Secret = "Edit secret", &m
				s.render(w, "edit", status, d)
				return
			}
		}
	}
	s.render(w, "secrets", status, d)
}
