// Package api implements the stateless HTTP client for datum-connectd.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultBaseURL = "http://127.0.0.1:47780"

// Client is safe for concurrent use. It stores no daemon state locally.
type Client struct {
	baseURL     string
	token       string
	http        *http.Client
	diagnostics io.Writer
}

// SetDiagnostics enables request metadata logging. Bodies and authorization
// headers are deliberately never logged.
func (c *Client) SetDiagnostics(w io.Writer) { c.diagnostics = w }

type HTTPError struct {
	StatusCode int
	Message    string
	RequestID  string
	Code       string
}

// TransportError distinguishes an unreachable daemon from a rejected operation.
type TransportError struct {
	URL     string
	Timeout bool
	Cause   error
}

func (e *TransportError) Error() string {
	if e.Timeout {
		return fmt.Sprintf("daemon request timed out: %v", e.Cause)
	}
	return fmt.Sprintf("contact daemon at %s: %v", e.URL, e.Cause)
}
func (e *TransportError) Unwrap() error { return e.Cause }

func (e *HTTPError) Error() string {
	request := ""
	if e.RequestID != "" {
		request = ", request_id=" + e.RequestID
	}
	return fmt.Sprintf("daemon: %s (HTTP %d%s)", e.Message, e.StatusCode, request)
}

func New(baseURL, token string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("daemon timeout must be greater than zero")
	}
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid daemon URL %q", baseURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("daemon URL must use http or https")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("daemon URL must be an origin without credentials, path, query, or fragment")
	}
	hostname := u.Hostname()
	ip := net.ParseIP(hostname)
	if !strings.EqualFold(hostname, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("daemon URL host must be localhost or a literal loopback address")
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   strings.TrimSpace(token),
		http: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Request performs one API request and returns its JSON response unchanged.
func (c *Client) Request(ctx context.Context, method, path, project string, body any) (json.RawMessage, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return nil, err
	}
	if project != "" {
		q := u.Query()
		q.Set("project", project)
		u.RawQuery = q.Encode()
	}

	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), r)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	started := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		if c.diagnostics != nil {
			fmt.Fprintf(c.diagnostics, "connect: %s %s failed after %s: %v\n", method, u.Redacted(), time.Since(started).Round(time.Millisecond), err)
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &TransportError{URL: c.baseURL, Timeout: true, Cause: err}
		}
		return nil, &TransportError{URL: c.baseURL, Cause: err}
	}
	defer resp.Body.Close()
	requestID := resp.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = resp.Header.Get("Traceparent")
	}
	if c.diagnostics != nil {
		fmt.Fprintf(c.diagnostics, "connect: %s %s -> HTTP %d in %s request_id=%q\n", method, u.Redacted(), resp.StatusCode, time.Since(started).Round(time.Millisecond), requestID)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read daemon response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(data, &envelope) == nil && envelope.Error != "" {
			return nil, &HTTPError{StatusCode: resp.StatusCode, Message: envelope.Error, RequestID: requestID, Code: envelope.Code}
		}
		message := strings.TrimSpace(string(data))
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return nil, &HTTPError{StatusCode: resp.StatusCode, Message: message, RequestID: requestID}
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("daemon returned invalid JSON")
	}
	return json.RawMessage(data), nil
}
