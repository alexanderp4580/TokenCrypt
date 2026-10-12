package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrSend is credential-free, including when the HTTP client's error contains
// a token in the request URL or Telegram echoes credentials in its response.
var ErrSend = errors.New("notify: Telegram delivery failed")

const sendTimeout = 10 * time.Second
const maxResponseBytes = 64 << 10

type telegram struct {
	endpoint string
	client   *http.Client
}

// NewTelegram uses the Telegram API when baseURL is empty. A custom URL and
// client support local HTTP boundary tests. The client is copied, with a timeout
// of at most ten seconds, and redirects are refused.
func NewTelegram(token string, client *http.Client, baseURL string) Transport {
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	var bounded http.Client
	if client != nil {
		bounded = *client
	}
	if bounded.Timeout <= 0 || bounded.Timeout > sendTimeout {
		bounded.Timeout = sendTimeout
	}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &telegram{strings.TrimRight(baseURL, "/") + "/bot" + url.PathEscape(token) + "/sendMessage", &bounded}
}

func (t *telegram) Send(chatID, text string) error { return t.send(context.Background(), chatID, text) }

func (t *telegram) send(ctx context.Context, chatID, text string) error {
	body, err := json.Marshal(struct {
		ChatID string `json:"chat_id"`
		Text   string `json:"text"`
	}{chatID, text})
	if err != nil {
		return ErrSend
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrSend
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := t.client.Do(req)
	if err != nil {
		return ErrSend
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return ErrSend
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(data) > maxResponseBytes {
		return ErrSend
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(data, &result) != nil || !result.OK {
		return ErrSend
	}
	return nil
}
