package web

import (
	"errors"
	"net/http"
	"strings"

	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

func (s *server) page(w http.ResponseWriter, name string, code int, x session, message, problem string) {
	d := pageData{Title: strings.ToUpper(name[:1]) + name[1:], Section: name, CSRF: x.csrf, Authenticated: true, State: s.svc.Status(), Choices: durationChoices, Message: message, Error: problem}
	if d.State.Error != "" {
		d.Error = "Secret list unavailable. Check the vault storage."
	}
	for _, m := range d.State.Secrets {
		if !m.Corrupt && m.Flag == nil {
			d.GrantSecrets = append(d.GrantSecrets, m)
		}
	}
	s.render(w, name, code, d)
}

var errMissingPassphrase = errors.New("web: missing passphrase")

func operationError(err error) (int, string) {
	switch {
	case errors.Is(err, errMissingPassphrase):
		return 400, "Enter a passphrase of at most 4096 bytes."
	case errors.Is(err, core.ErrThrottled):
		return 429, "Too many attempts. Try again later."
	case errors.Is(err, core.ErrWrongPassphrase):
		return 400, "Passphrase not accepted."
	case errors.Is(err, vault.ErrBadName):
		return 400, "Use a name starting with a lowercase letter, followed by lowercase letters, digits or underscores (up to 64 characters)."
	case errors.Is(err, vault.ErrBadExpiry):
		return 400, "Choose a valid expiry date (YYYY-MM-DD), or Never."
	case errors.Is(err, vault.ErrTooLarge):
		return 400, "Secret values must be at most 1 MiB."
	case errors.Is(err, vault.ErrExists):
		return 400, "That secret name already exists."
	case errors.Is(err, vault.ErrNotFound):
		return 400, "Secret unavailable."
	case errors.Is(err, core.ErrFlagged):
		return 400, "Clear the flag before granting access."
	case errors.Is(err, core.ErrBadFlag):
		return 400, "Choose leaked or invalid."
	case errors.Is(err, core.ErrNotPending), errors.Is(err, core.ErrRequestMismatch):
		return 400, "Request unavailable. Refresh the pending requests."
	case errors.Is(err, vault.ErrMetadata):
		return 500, "The secret changed, but its metadata could not be saved. Check the vault storage."
	case errors.Is(err, core.ErrAudit):
		return 500, "The action may have completed, but its audit record could not be saved. Check the current state before retrying."
	default:
		return 500, "Operation could not be completed. Check the current state before retrying."
	}
}

func (s *server) result(w http.ResponseWriter, r *http.Request, x session, page string, err error) {
	if err != nil {
		status, message := operationError(err)
		s.page(w, page, status, x, "", message)
		return
	}
	http.Redirect(w, r, "/"+page, http.StatusSeeOther)
}

func (s *server) edit(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "GET") {
		return
	}
	name := r.URL.Query().Get("name")
	if !vault.ValidName(name) {
		s.result(w, r, x, "secrets", vault.ErrBadName)
		return
	}
	for _, m := range s.svc.Status().Secrets {
		if m.Name != name {
			continue
		}
		if m.Corrupt {
			s.page(w, "secrets", 400, x, "", "Damaged file. You can delete it with your passphrase.")
			return
		}
		s.render(w, "edit", 200, pageData{Title: "Edit secret", Section: "secrets", CSRF: x.csrf, Authenticated: true, Secret: &m})
		return
	}
	s.result(w, r, x, "secrets", vault.ErrNotFound)
}

func (s *server) secretAction(w http.ResponseWriter, r *http.Request, x session) {
	if !method(w, r, "POST") {
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/secrets/")
	switch action {
	case "create", "update", "rename", "delete", "description", "expiry", "flag", "clear":
	default:
		http.NotFound(w, r)
		return
	}
	name := r.PostForm.Get("name")
	if !vault.ValidName(name) {
		s.secretError(w, r, x, vault.ErrBadName)
		return
	}
	if action != "create" && action != "delete" {
		for _, m := range s.svc.Status().Secrets {
			if m.Name == name && m.Corrupt {
				s.page(w, "secrets", 400, x, "", "Damaged file. You can delete it with your passphrase.")
				return
			}
		}
	}
	desc := r.PostForm.Get("description")
	if (action == "create" || action == "update") && len(r.PostForm.Get("value")) > vault.MaxValueBytes {
		s.secretError(w, r, x, vault.ErrTooLarge)
		return
	}
	if action == "rename" && !vault.ValidName(r.PostForm.Get("new_name")) {
		s.secretError(w, r, x, vault.ErrBadName)
		return
	}
	var date string
	var err error
	if action == "create" || action == "expiry" {
		date, err = s.formExpiry(r)
		if err != nil {
			s.secretError(w, r, x, err)
			return
		}
	}
	if action == "expiry" {
		err = s.svc.SetExpiry(name, date)
	} else if action == "description" {
		err = s.svc.SetDescription(name, desc)
	} else if action == "flag" {
		err = s.svc.Flag(name, r.PostForm.Get("kind"), r.PostForm.Get("reason"), "user")
	} else {
		pass, ok := passphrase(r)
		if !ok {
			s.secretError(w, r, x, errMissingPassphrase)
			return
		}
		defer crypto.Zero(pass)
		switch action {
		case "create", "update":
			value := []byte(r.PostForm.Get("value"))
			defer crypto.Zero(value)
			if action == "create" {
				err = s.svc.CreateWithExpiry(name, desc, value, pass, "user", date)
			} else {
				err = s.svc.UpdateValue(name, value, pass, "user")
			}
		case "rename":
			err = s.svc.Rename(name, r.PostForm.Get("new_name"), pass, "user")
		case "delete":
			err = s.svc.Delete(name, pass, "user")
		case "clear":
			err = s.svc.ClearFlag(name, pass, "user")
		}
	}
	if err != nil {
		s.secretError(w, r, x, err)
		return
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}
