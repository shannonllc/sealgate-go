package sealgate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"
)

// MaxRateLimitWait is the longest wait honoured for a 429 (the rate limit window is one minute).
const MaxRateLimitWait = 60 * time.Second

const (
	backoffBase = 500 * time.Millisecond
	backoffMax  = 8 * time.Second
)

// backoff is exponential with ±25% jitter. attempt starts at 0.
func backoff(attempt int, random func() float64) time.Duration {
	base := float64(backoffBase) * math.Pow(2, float64(attempt))
	if base > float64(backoffMax) {
		base = float64(backoffMax)
	}
	return time.Duration(math.Round(base * (0.75 + random()*0.5)))
}

// rateLimitWait is the wait before retrying a 429, from retry-after.
func rateLimitWait(h http.Header, now time.Time) (time.Duration, bool) {
	return parseRetryAfter(h.Get("retry-after"), now)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type request struct {
	method string
	path   string
	// query is sent as is: build it with only the values to send ("" is sent as an empty value).
	query url.Values
	body  any // nil sends no body
	// idempotent: safe to send twice (GET, PATCH, DELETE). 5xx, timeouts and connection errors are retried only for
	// these. 429 is always retried: the API rejects it before doing anything.
	idempotent bool
}

type outcome struct {
	err       *Error
	retryable bool
	wait      time.Duration
	hasWait   bool
}

func (c *Client) url(path string, query url.Values) string {
	if s := query.Encode(); s != "" {
		return c.baseURL + path + "?" + s
	}
	return c.baseURL + path
}

// do sends req with retries and decodes a 2xx JSON body into out (when out is not nil).
func (c *Client) do(ctx context.Context, req request, out any, rc requestConfig) error {
	var payload []byte
	if req.body != nil {
		b, err := json.Marshal(req.body)
		if err != nil {
			return newError(KindInvalidArgument, "Could not encode the request body: "+err.Error(), err)
		}
		payload = b
	}
	for attempt := 0; ; attempt++ {
		o := c.once(ctx, req, payload, out, rc.timeout)
		if o == nil {
			return nil
		}
		if !o.retryable || attempt >= rc.maxRetries || ctx.Err() != nil {
			return o.err
		}
		wait := o.wait
		if !o.hasWait {
			wait = backoff(attempt, c.random)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return newError(KindConnection, "Request was aborted", err)
		}
	}
}

func (c *Client) once(ctx context.Context, req request, payload []byte, out any, timeout time.Duration) *outcome {
	if err := ctx.Err(); err != nil {
		return &outcome{err: newError(KindConnection, "Request was aborted", err)}
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	hr, err := http.NewRequestWithContext(actx, req.method, c.url(req.path, req.query), body)
	if err != nil {
		return &outcome{err: newError(KindInvalidArgument, "Invalid request: "+err.Error(), err)}
	}
	hr.Header.Set("Authorization", "Bearer "+c.apiKey)
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", UserAgent)
	if payload != nil {
		hr.Header.Set("Content-Type", "application/json")
	}

	res, err := c.httpClient.Do(hr)
	var text []byte
	if err == nil {
		text, err = io.ReadAll(res.Body)
		res.Body.Close()
	}
	if err != nil {
		if ctx.Err() != nil {
			return &outcome{err: newError(KindConnection, "Request was aborted", err)}
		}
		var ne net.Error
		if errors.Is(actx.Err(), context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return &outcome{err: newError(KindTimeout, fmt.Sprintf("Request timed out after %s", timeout), err), retryable: req.idempotent}
		}
		return &outcome{err: newError(KindConnection, "Connection error: "+err.Error(), err), retryable: req.idempotent}
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if len(text) == 0 {
			return nil
		}
		if !json.Valid(text) {
			e := &Error{Kind: KindAPI, Status: res.StatusCode, Message: fmt.Sprintf("Invalid JSON in response (HTTP %d)", res.StatusCode)}
			return &outcome{err: e}
		}
		if out != nil {
			if err := json.Unmarshal(text, out); err != nil {
				e := &Error{Kind: KindAPI, Status: res.StatusCode, Message: fmt.Sprintf("Unexpected response (HTTP %d): %s", res.StatusCode, err), Err: err}
				return &outcome{err: e}
			}
		}
		return nil
	}
	e := errorFromResponse(res.StatusCode, text, res.Header, c.now())
	if res.StatusCode == http.StatusTooManyRequests {
		wait, ok := rateLimitWait(res.Header, c.now())
		if ok && wait > MaxRateLimitWait {
			return &outcome{err: e}
		}
		return &outcome{err: e, retryable: true, wait: wait, hasWait: ok}
	}
	return &outcome{err: e, retryable: res.StatusCode >= 500 && req.idempotent}
}
