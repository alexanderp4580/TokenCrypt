// Package api serves the agent's four operations over a private Unix socket.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tokencrypt/internal/core"
	"tokencrypt/internal/crypto"
	"tokencrypt/internal/vault"
)

var (
	ErrSocket      = errors.New("api: socket unavailable or unsafe")
	ErrUnavailable = errors.New("api: operation unavailable")
	ErrProtocol    = errors.New("api: invalid response")
)

const maxBodyBytes = 8192

type input struct {
	Name     string        `json:"name"`
	Reason   string        `json:"reason,omitempty"`
	Kind     string        `json:"kind,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
	Wait     time.Duration `json:"wait,omitempty"`
}

type wireError struct {
	Code string `json:"code"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
}

type response struct {
	Value   []byte        `json:"value,omitempty"`
	Request *core.Request `json:"request,omitempty"`
	Status  *core.Status  `json:"status,omitempty"`
	Error   *wireError    `json:"error,omitempty"`
}

// Serve runs until ctx ends. It refuses another active listener and removes
// only its own socket on shutdown. All accepted connections need the same uid.
func Serve(ctx context.Context, svc *core.Service, socketPath string) error {
	return serve(ctx, svc, socketPath, peerUID)
}

func serve(ctx context.Context, svc *core.Service, path string, peer func(*net.UnixConn) (uint32, error)) error {
	if svc == nil {
		return ErrUnavailable
	}
	if ctx.Err() != nil {
		return nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return ErrSocket
	}
	dir, err := lockDirectory(filepath.Dir(path))
	if err != nil {
		return ErrSocket
	}
	defer dir.Close()
	if err := prepareSocket(path); err != nil {
		return ErrSocket
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return ErrSocket
	}
	l.SetUnlinkOnClose(false)
	fi, err := os.Lstat(path)
	if err != nil {
		_ = l.Close()
		return ErrSocket
	}
	defer func() {
		_ = l.Close()
		current, err := os.Lstat(path)
		if err == nil && current.Mode()&os.ModeSocket != 0 && os.SameFile(fi, current) {
			_ = os.Remove(path)
		}
	}()
	if err := os.Chmod(path, 0600); err != nil {
		return ErrSocket
	}
	server := &http.Server{
		Handler:           handler(svc),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192,
		BaseContext:    func(net.Listener) context.Context { return ctx },
		ErrorLog:       log.New(io.Discard, "", 0),
	}
	defer server.Close()
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-stopped:
		}
	}()
	err = server.Serve(&checkedListener{UnixListener: l, uid: uint32(os.Geteuid()), peer: peer})
	close(stopped)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return ErrUnavailable
}

// lockDirectory holds a kernel lock through socket cleanup, so competing
// servers cannot remove a socket between its stale check and bind.
func lockDirectory(dir string) (*os.File, error) {
	if dir == string(filepath.Separator) {
		return nil, ErrSocket
	}
	for p := dir; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err == nil && (!fi.IsDir() || fi.Mode()&os.ModeSymlink != 0) {
			return nil, ErrSocket
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, ErrSocket
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, ErrSocket
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrSocket
	}
	f := os.NewFile(uintptr(fd), dir)
	fi, err := f.Stat()
	current, statErr := os.Lstat(dir)
	if err != nil || statErr != nil || !owned(fi) || !os.SameFile(fi, current) {
		_ = f.Close()
		return nil, ErrSocket
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrSocket
	}
	if err := f.Chmod(0700); err != nil {
		_ = f.Close()
		return nil, ErrSocket
	}
	return f, nil
}

// prepareSocket runs under the directory lock and removes a same-owned
// socket only after the kernel reports that no listener exists.
func prepareSocket(path string) error {
	old, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || old.Mode()&os.ModeSocket == 0 || !owned(old) {
		return ErrSocket
	}
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return ErrSocket
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return ErrSocket
	}
	now, err := os.Lstat(path)
	if err != nil || now.Mode()&os.ModeSocket == 0 || !os.SameFile(old, now) {
		return ErrSocket
	}
	return os.Remove(path)
}

func owned(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}

type checkedListener struct {
	*net.UnixListener
	uid  uint32
	peer func(*net.UnixConn) (uint32, error)
}

func (l *checkedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := l.peer(c)
		if err == nil && uid == l.uid {
			return c, nil
		}
		_ = c.Close()
	}
}

func handler(s *core.Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		method := "POST"
		switch r.URL.Path {
		case "/status":
			method = "GET"
		case "/read", "/request", "/flag":
		default:
			writeResponse(w, 404, response{Error: &wireError{Code: "not_found"}})
			return
		}
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeResponse(w, 405, response{Error: &wireError{Code: "method"}})
			return
		}
		if r.URL.Path == "/status" {
			st := s.Status()
			writeResponse(w, 200, response{Status: &st})
			return
		}
		var in input
		// Each operation accepts only its own fields; clients cannot supply an actor.
		var dst any
		switch r.URL.Path {
		case "/read":
			dst = &struct {
				Name *string `json:"name"`
			}{Name: &in.Name}
		case "/request":
			dst = &struct {
				Name     *string        `json:"name"`
				Reason   *string        `json:"reason"`
				Duration *time.Duration `json:"duration"`
				Wait     *time.Duration `json:"wait"`
			}{&in.Name, &in.Reason, &in.Duration, &in.Wait}
		case "/flag":
			dst = &struct {
				Name   *string `json:"name"`
				Kind   *string `json:"kind"`
				Reason *string `json:"reason"`
			}{&in.Name, &in.Kind, &in.Reason}
		}
		if code := decodeInput(w, r, dst); code != 0 {
			writeResponse(w, code, response{Error: &wireError{Code: "bad_request"}})
			return
		}
		if in.Wait < 0 {
			writeResponse(w, 400, response{Error: &wireError{Code: "bad_request"}})
			return
		}
		var out response
		var err error
		switch r.URL.Path {
		case "/read":
			out.Value, err = s.Read(in.Name)
			defer crypto.Zero(out.Value)
		case "/flag":
			err = s.Flag(in.Name, in.Kind, in.Reason, "agent")
		case "/request":
			var req core.Request
			req, err = s.Request(in.Name, in.Reason, in.Duration)
			if err == nil && in.Wait > 0 {
				ctx, cancel := context.WithTimeout(r.Context(), in.Wait)
				req, err = s.Wait(ctx, req.ID)
				cancel()
			}
			if req.ID != "" {
				out.Request = &req
			}
		}
		code := 200
		if err != nil {
			out.Error, code = encodeError(err)
		}
		writeResponse(w, code, out)
	})
}

func decodeInput(w http.ResponseWriter, r *http.Request, dst any) int {
	typ, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" {
		return 400
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	// Check for an object first: decoding null into a struct would succeed.
	dec := json.NewDecoder(r.Body)
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			return 413
		}
		return 400
	}
	if len(raw) == 0 || raw[0] != '{' {
		return 400
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			return 413
		}
		return 400
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return 400
	}
	return 0
}

func writeResponse(w http.ResponseWriter, code int, out response) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(out)
}

func encodeError(err error) (*wireError, int) {
	var flag *core.FlaggedError
	if errors.As(err, &flag) && vault.ValidName(flag.Secret) && (flag.Kind == "leaked" || flag.Kind == "invalid") {
		return &wireError{Code: "flagged", Name: flag.Secret, Kind: flag.Kind}, 403
	}
	for _, row := range errorCodes {
		if errors.Is(err, row.err) {
			return &wireError{Code: row.code}, row.status
		}
	}
	return &wireError{Code: "unavailable"}, 500
}

type errorCode struct {
	err    error
	code   string
	status int
}

var errorCodes = []errorCode{
	{core.ErrLocked, "locked", 403}, {core.ErrNoGrant, "no_grant", 403},
	{core.ErrNotFound, "not_found", 404}, {vault.ErrBadName, "bad_name", 400},
	{core.ErrBadFlag, "bad_flag", 400}, {core.ErrDurationTooLong, "duration", 400},
	{core.ErrTooManyPending, "pending_limit", 429},
	{context.DeadlineExceeded, "timeout", 408}, {context.Canceled, "canceled", 408},
}
