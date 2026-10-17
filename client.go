// Package sealgate is the Go SDK for SealGate (https://sealgate.jp/), the passkey authentication API that adds
// passkey login to your existing login: start and finish passkey registration and login on your server, manage
// users and passkeys, issue recovery tokens, read the audit log and stats, and verify webhooks.
//
// Use it on your server only: never ship the API key to a browser or an app.
package sealgate

import (
	"context"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the public API.
	DefaultBaseURL = "https://api.sealgate.jp"
	// DefaultTimeout is the time allowed for each attempt.
	DefaultTimeout = 30 * time.Second
	// DefaultMaxRetries is the number of retries after the first attempt.
	DefaultMaxRetries = 2
	// APIKeyEnv is read when the API key argument is empty.
	APIKeyEnv = "SEALGATE_API_KEY"
)

// Client for the SealGate API (/v1). It is safe for concurrent use.
type Client struct {
	Register    *RegisterService
	Login       *LoginService
	Users       *UsersService
	Credentials *CredentialsService
	Recovery    *RecoveryService
	Apps        *AppsService

	apiKey     string
	baseURL    string
	timeout    time.Duration
	maxRetries int
	httpClient *http.Client

	// replaced in tests
	sleep  func(ctx context.Context, d time.Duration) error
	random func() float64
	now    func() time.Time
}

// Option configures a [Client].
type Option func(*Client)

// WithBaseURL sets the API origin. Default https://api.sealgate.jp.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithTimeout sets the time allowed for each attempt. Default 30 seconds.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// WithMaxRetries sets the retries after the first attempt. Default 2. 0 disables retries.
func WithMaxRetries(n int) Option { return func(c *Client) { c.maxRetries = n } }

// WithHTTPClient sets the HTTP client. Default: a new http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// NewClient creates a client. apiKey is sk_live_… or sk_test_…; when empty, SEALGATE_API_KEY is used.
func NewClient(apiKey string, opts ...Option) (*Client, error) {
	key := apiKey
	if key == "" {
		key = strings.TrimSpace(os.Getenv(APIKeyEnv))
	}
	if key == "" {
		return nil, newError(KindInvalidArgument, "Missing API key. Pass it to sealgate.NewClient(\"sk_…\") or set "+APIKeyEnv+".", nil)
	}
	c := &Client{
		apiKey:     key,
		baseURL:    DefaultBaseURL,
		timeout:    DefaultTimeout,
		maxRetries: DefaultMaxRetries,
		sleep:      sleepContext,
		random:     rand.Float64,
		now:        time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	if c.httpClient == nil {
		c.httpClient = &http.Client{}
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	c.Register = &RegisterService{c}
	c.Login = &LoginService{c}
	c.Users = &UsersService{c}
	c.Credentials = &CredentialsService{c}
	c.Recovery = &RecoveryService{c}
	c.Apps = &AppsService{c}
	return c, nil
}

// BaseURL returns the API origin without a trailing slash.
func (c *Client) BaseURL() string { return c.baseURL }

// RequestOption overrides client settings for one call.
type RequestOption func(*requestConfig)

type requestConfig struct {
	timeout    time.Duration
	maxRetries int
}

// WithRequestTimeout sets the time allowed for each attempt of this call.
func WithRequestTimeout(d time.Duration) RequestOption {
	return func(r *requestConfig) { r.timeout = d }
}

// WithRequestMaxRetries sets the retries after the first attempt for this call.
func WithRequestMaxRetries(n int) RequestOption {
	return func(r *requestConfig) { r.maxRetries = n }
}

func (c *Client) config(opts []RequestOption) requestConfig {
	r := requestConfig{timeout: c.timeout, maxRetries: c.maxRetries}
	for _, o := range opts {
		o(&r)
	}
	return r
}

// String returns a pointer to s, for optional fields.
func String(s string) *string { return &s }

// Bool returns a pointer to b, for optional fields (such as RegisterOptionsParams.SignedIn).
func Bool(b bool) *bool { return &b }
