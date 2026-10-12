package web

import (
	"encoding/json"
	"net/http"

	"tokencrypt/internal/audit"
)

type auditRow struct {
	Event                   audit.Event
	Kind, FlagActor, Reason string
}

func (s *server) auditPage(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "GET") {
		return
	}
	d := pageData{Title: "Audit", Section: "audit", CSRF: x.csrf, Authenticated: true}
	events, err := s.svc.AuditTail(100)
	if err != nil {
		d.Error = "Audit log unavailable."
		s.render(w, "audit", 500, d)
		return
	}
	for _, event := range events {
		row := auditRow{Event: event}
		if event.Type == audit.FlagSet || event.Type == audit.FlagCleared {
			var detail struct{ Kind, Actor, Reason string }
			if json.Unmarshal([]byte(event.Detail), &detail) == nil {
				row.Kind, row.FlagActor, row.Reason = detail.Kind, detail.Actor, detail.Reason
			}
		}
		// Render structured flag detail only. Other details can contain notifier
		// chat IDs or storage diagnostics and do not belong in the page.
		row.Event.Detail = ""
		d.Audit = append(d.Audit, row)
	}
	s.render(w, "audit", 200, d)
}
