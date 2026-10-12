// Package cli implements the agent's commands over the private socket API.
package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"tokencrypt/internal/api"
	"tokencrypt/internal/core"
	"tokencrypt/internal/vault"
)

type command struct {
	kind, name, reason, flagKind string
	names, child                 []string
	duration, wait               time.Duration
}

// Run validates arguments before dialing. It returns 0 on success, 1 on an
// operation failure, 2 on usage errors, or a launched child's exit status.
func Run(args []string, stdout, stderr io.Writer, dial func() (*api.Client, error)) int {
	c, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, "usage: tokencrypt get NAME | run --with NAME[,NAME] -- CMD... | request NAME [--for DURATION] [--reason TEXT] [--wait DURATION] | status | flag NAME --kind leaked|invalid [--reason TEXT]")
		return 2
	}
	client, err := dial()
	if err != nil {
		fmt.Fprintln(stderr, "tokencrypt: cannot connect to daemon socket")
		return 1
	}
	defer client.Close()
	switch c.kind {
	case "get":
		value, err := client.Read(c.name)
		if err != nil {
			return failed(stderr, err)
		}
		defer clear(value)
		if n, err := stdout.Write(value); err != nil || n != len(value) {
			fmt.Fprintln(stderr, "tokencrypt: cannot write value to stdout")
			return 1
		}
	case "run":
		return runChild(c, client, stdout, stderr)
	case "request":
		r, err := client.Request(c.name, c.reason, c.duration, c.wait)
		if r.ID != "" {
			printRequest(stdout, r)
		}
		if err != nil {
			return failed(stderr, err)
		}
		if r.State == core.StateDenied || r.State == core.StateExpired {
			fmt.Fprintf(stderr, "tokencrypt: request %s\n", r.State)
			return 1
		}
	case "flag":
		if err := client.Flag(c.name, c.flagKind, c.reason); err != nil {
			return failed(stderr, err)
		}
	case "status":
		st, err := client.Status()
		if err != nil {
			return failed(stderr, err)
		}
		printStatus(stdout, st)
	}
	return 0
}

func parse(args []string) (command, error) {
	bad := errors.New("invalid arguments")
	var c command
	if len(args) == 0 {
		return c, bad
	}
	c.kind = args[0]
	args = args[1:]
	switch c.kind {
	case "get":
		if len(args) != 1 || !vault.ValidName(args[0]) {
			return c, bad
		}
		c.name = args[0]
	case "status":
		if len(args) != 0 {
			return c, bad
		}
	case "run":
		separator := -1
		for i, arg := range args {
			if arg == "--" {
				separator = i
				break
			}
		}
		if separator < 0 || separator == len(args)-1 {
			return c, bad
		}
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		var names string
		fs.StringVar(&names, "with", "", "")
		if err := fs.Parse(args[:separator]); err != nil || fs.NArg() != 0 {
			return c, bad
		}
		seen := make(map[string]bool)
		for _, name := range strings.Split(names, ",") {
			if !vault.ValidName(name) || seen[name] {
				return c, bad
			}
			seen[name] = true
			c.names = append(c.names, name)
		}
		c.child = args[separator+1:]
	case "request", "flag":
		if len(args) == 0 || !vault.ValidName(args[0]) {
			return c, bad
		}
		c.name = args[0]
		fs := flag.NewFlagSet(c.kind, flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.StringVar(&c.reason, "reason", "", "")
		if c.kind == "request" {
			fs.DurationVar(&c.duration, "for", 10*time.Minute, "")
			fs.DurationVar(&c.wait, "wait", 0, "")
		} else {
			fs.StringVar(&c.flagKind, "kind", "", "")
		}
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
			return c, bad
		}
		if c.kind == "request" {
			if c.duration <= 0 || c.duration > 90*24*time.Hour || c.wait < 0 {
				return c, bad
			}
		} else if c.flagKind != "leaked" && c.flagKind != "invalid" {
			return c, bad
		}
	default:
		return c, bad
	}
	return c, nil
}

func runChild(c command, client *api.Client, stdout, stderr io.Writer) int {
	env := os.Environ()
	for _, name := range c.names {
		value, err := client.Read(name)
		if err != nil {
			return failed(stderr, err)
		}
		envName := strings.ToUpper(name)
		// Linux MAX_ARG_STRLEN includes the name, '=', value and final NUL.
		if bytes.IndexByte(value, 0) >= 0 || len(envName)+1+len(value)+1 > 128*1024 {
			clear(value)
			fmt.Fprintf(stderr, "tokencrypt: %s cannot fit in an environment string; use get\n", name)
			return 1
		}
		prefix := envName + "="
		kept := env[:0]
		for _, entry := range env {
			if !strings.HasPrefix(entry, prefix) {
				kept = append(kept, entry)
			}
		}
		env = append(kept, prefix+string(value))
		clear(value)
	}
	child := exec.Command(c.child[0], c.child[1:]...)
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, stdout, stderr
	if err := child.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			if code := exit.ExitCode(); code >= 0 {
				return code
			}
			if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				return 128 + int(status.Signal())
			}
		}
		fmt.Fprintln(stderr, "tokencrypt: cannot run child command; for environment limits use get")
		return 1
	}
	return 0
}

func failed(stderr io.Writer, err error) int {
	var flagged *core.FlaggedError
	switch {
	case errors.As(err, &flagged):
		fmt.Fprintf(stderr, "tokencrypt: secret %q is flagged %q\n", flagged.Secret, flagged.Kind)
	case errors.Is(err, core.ErrNoGrant):
		fmt.Fprintln(stderr, "tokencrypt: no live grant for secret")
	case errors.Is(err, core.ErrLocked):
		fmt.Fprintln(stderr, "tokencrypt: daemon is locked; unlock it through the website")
	case errors.Is(err, core.ErrNotFound):
		fmt.Fprintln(stderr, "tokencrypt: secret not found")
	case errors.Is(err, core.ErrTooManyPending):
		fmt.Fprintln(stderr, "tokencrypt: too many pending requests")
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(stderr, "tokencrypt: request wait timed out")
	case errors.Is(err, core.ErrAudit):
		fmt.Fprintln(stderr, "tokencrypt: audit record failed; check status before retrying")
	default:
		fmt.Fprintln(stderr, "tokencrypt: operation failed")
	}
	return 1
}

func printRequest(out io.Writer, r core.Request) {
	fmt.Fprintf(out, "request id=%q secret=%q state=%q duration=%s reason=%q created=%q\n", r.ID, r.Secret, r.State, r.Duration, r.Reason, stamp(r.Created))
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func printStatus(out io.Writer, st core.Status) {
	fmt.Fprintf(out, "locked=%t\n", st.Locked)
	if st.Error != "" {
		fmt.Fprintf(out, "error=%q\n", st.Error)
	}
	for _, s := range st.Secrets {
		expiry := s.ExpiresOn
		if expiry == "" {
			expiry = "Never"
		}
		fmt.Fprintf(out, "secret name=%q description=%q created=%q updated=%q last_granted=%q token_expires_on=%q corrupt=%t\n", s.Name, s.Description, stamp(s.Created), stamp(s.Updated), stamp(s.LastGranted), expiry, s.Corrupt)
		if s.Flag != nil {
			fmt.Fprintf(out, "flag secret=%q kind=%q actor=%q reason=%q time=%q\n", s.Name, s.Flag.Kind, s.Flag.Actor, s.Flag.Reason, stamp(s.Flag.At))
		}
	}
	now := time.Now()
	for _, g := range st.Grants {
		left := g.Expires.Sub(now)
		if left < 0 {
			left = 0
		}
		fmt.Fprintf(out, "grant id=%q secret=%q left=%s expires=%q granted_by=%q request_id=%q\n", g.ID, g.Secret, left.Round(time.Second), stamp(g.Expires), g.GrantedBy, g.RequestID)
	}
	for _, r := range st.Pending {
		printRequest(out, r)
	}
}
