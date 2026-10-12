package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"tokencrypt/internal/core"
	"tokencrypt/internal/vault"
)

// Client talks only to a Unix socket. It is safe for concurrent calls.
type Client struct {
	http      *http.Client
	transport *http.Transport
}

// Dial checks that the socket can be reached, then creates a JSON client.
func Dial(socketPath string) (*Client, error) {
	c, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return nil, ErrSocket
	}
	_ = c.Close()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns: 4, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport: tr}, nil
}

// Close releases idle connections. Calls in progress retain their connection.
func (c *Client) Close() { c.transport.CloseIdleConnections() }

// Read returns a byte-for-byte copy of a granted secret.
func (c *Client) Read(name string) ([]byte, error) {
	out, err := c.call("/read", input{Name: name})
	if err != nil {
		return nil, err
	}
	if len(out.Value) > vault.MaxValueBytes {
		return nil, ErrProtocol
	}
	return out.Value, nil
}

// Request creates a request and optionally waits for its final state. A wait
// timeout returns the pending request alongside context.DeadlineExceeded.
func (c *Client) Request(name, reason string, d, wait time.Duration) (core.Request, error) {
	out, err := c.call("/request", input{Name: name, Reason: reason, Duration: d, Wait: wait})
	if out.Request != nil {
		return *out.Request, err
	}
	if err != nil {
		return core.Request{}, err
	}
	return core.Request{}, ErrProtocol
}

// Flag records the agent's leaked or invalid flag; it cannot clear a flag.
func (c *Client) Flag(name, kind, reason string) error {
	_, err := c.call("/flag", input{Name: name, Kind: kind, Reason: reason})
	return err
}

// Status returns metadata, grants and pending requests without secret values.
func (c *Client) Status() (core.Status, error) {
	out, err := c.call("/status", input{})
	if err != nil {
		return core.Status{}, err
	}
	if out.Status == nil {
		return core.Status{}, ErrProtocol
	}
	return *out.Status, nil
}

func (c *Client) call(path string, in input) (response, error) {
	var out response
	method := "POST"
	var body io.Reader
	if path == "/status" {
		method = "GET"
	} else {
		b, err := json.Marshal(in)
		if err != nil {
			return out, ErrProtocol
		}
		body = bytes.NewReader(b)
	}
	timeout := 10 * time.Second
	if in.Wait > 0 {
		if in.Wait > time.Duration(math.MaxInt64)-timeout {
			timeout = time.Duration(math.MaxInt64)
		} else {
			timeout += in.Wait
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, body)
	if err != nil {
		return out, ErrProtocol
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := c.http.Do(req)
	if err != nil {
		return out, ErrUnavailable
	}
	defer r.Body.Close()
	const maxResponse = 32 << 20
	b, err := io.ReadAll(io.LimitReader(r.Body, maxResponse+1))
	if err != nil || len(b) > maxResponse {
		return out, ErrProtocol
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&out); err != nil {
		return response{}, ErrProtocol
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return response{}, ErrProtocol
	}
	if out.Error != nil {
		return out, decodeError(out.Error)
	}
	if r.StatusCode != 200 {
		return response{}, ErrProtocol
	}
	return out, nil
}

func decodeError(e *wireError) error {
	if e.Code == "flagged" {
		if !vault.ValidName(e.Name) || (e.Kind != "leaked" && e.Kind != "invalid") {
			return ErrProtocol
		}
		return &core.FlaggedError{Secret: e.Name, Kind: e.Kind}
	}
	for _, row := range errorCodes {
		if row.code == e.Code {
			return row.err
		}
	}
	if e.Code == "bad_request" {
		return ErrProtocol
	}
	return ErrUnavailable
}
