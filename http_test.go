package sealgate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var app = map[string]any{"id": "app_1"}

func apiError(status int, code, message string, headers ...string) reply {
	return jsonReply(status, map[string]any{"error": map[string]any{"code": code, "message": message}}, headers...)
}

func TestClientOptions(t *testing.T) {
	t.Run("headers", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, app))
		c, _ := testClient(t, f)
		if _, err := c.Apps.Get(context.Background(), "app_1"); err != nil {
			t.Fatal(err)
		}
		h := f.Last().Header
		for k, want := range map[string]string{"Authorization": "Bearer sk_test_abc", "Accept": "application/json", "User-Agent": "sealgate-go/" + Version} {
			if got := h.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if h.Get("Content-Type") != "" || len(f.Last().Raw) != 0 {
			t.Errorf("GET sent a body")
		}
	})

	t.Run("body and content type", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"challenge_id": "chl_1", "options": map[string]any{"challenge": "c"}}))
		c, _ := testClient(t, f)
		r, err := c.Login.Options(context.Background(), &LoginOptionsParams{ExternalID: "山田"})
		if err != nil || r.ChallengeID != "chl_1" || string(r.Options) != `{"challenge":"c"}` {
			t.Fatal(r, err)
		}
		if f.Last().Header.Get("Content-Type") != "application/json" || string(f.Last().Raw) != `{"external_id":"山田"}` {
			t.Fatal(string(f.Last().Raw))
		}
	})

	t.Run("user agent format", func(t *testing.T) {
		if !regexp.MustCompile(`^sealgate-go/\d+\.\d+\.\d+$`).MatchString(UserAgent) {
			t.Fatal(UserAgent)
		}
	})

	t.Run("api key from env", func(t *testing.T) {
		t.Setenv(APIKeyEnv, " sk_live_env ")
		f := newFakeAPI(t, jsonReply(200, app))
		c, err := NewClient("", WithBaseURL(f.srv.URL))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = c.Apps.Get(context.Background(), "app_1")
		if got := f.Last().Header.Get("Authorization"); got != "Bearer sk_live_env" {
			t.Fatal(got)
		}
	})

	t.Run("missing api key", func(t *testing.T) {
		t.Setenv(APIKeyEnv, "  ")
		_, err := NewClient("")
		if !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), APIKeyEnv) {
			t.Fatal(err)
		}
	})

	t.Run("base url and options", func(t *testing.T) {
		c, _ := NewClient("sk_test_x")
		if c.BaseURL() != "https://api.sealgate.jp" {
			t.Fatal(c.BaseURL())
		}
		c, _ = NewClient("sk_test_x", WithBaseURL("http://localhost:3003//"))
		if c.BaseURL() != "http://localhost:3003" {
			t.Fatal(c.BaseURL())
		}
		if c.timeout != DefaultTimeout || c.maxRetries != DefaultMaxRetries || c.httpClient == nil {
			t.Fatal("defaults")
		}
		h := &http.Client{}
		c, _ = NewClient("sk_test_x", WithHTTPClient(h), WithTimeout(time.Second), WithMaxRetries(5))
		if c.httpClient != h || c.timeout != time.Second || c.maxRetries != 5 {
			t.Fatal("options")
		}
	})

	t.Run("version matches the changelog", func(t *testing.T) {
		b, err := os.ReadFile("CHANGELOG.md")
		if err != nil || !strings.Contains(string(b), "## "+Version) {
			t.Fatal("CHANGELOG.md has no entry for", Version)
		}
	})
}

func TestErrors(t *testing.T) {
	cases := []struct {
		status   int
		code     string
		kind     Kind
		sentinel error
	}{
		{400, "invalid_request", KindValidation, ErrValidation},
		{401, "invalid_api_key", KindAuthentication, ErrAuthentication},
		{401, "verification_failed", KindVerification, ErrVerification},
		{402, "mau_limit", KindPaymentRequired, ErrPaymentRequired},
		{403, "credential_revoked", KindPermission, ErrPermission},
		{403, "origin_not_allowed", KindPermission, ErrPermission},
		{404, "not_found", KindNotFound, ErrNotFound},
		{410, "challenge_expired", KindChallengeExpired, ErrChallengeExpired},
		{418, "teapot", KindAPI, ErrAPI},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			f := newFakeAPI(t, apiError(tc.status, tc.code, "m"))
			c, _ := testClient(t, f)
			_, err := c.Login.Verify(context.Background(), &LoginVerifyParams{ChallengeID: "c", Response: json.RawMessage(`{}`)})
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("%T", err)
			}
			if e.Kind != tc.kind || e.Status != tc.status || e.Code != tc.code || e.Message != "m" {
				t.Fatalf("%+v", e)
			}
			if !errors.Is(err, tc.sentinel) || errors.Is(err, ErrConnection) || err.Error() != "m" {
				t.Fatal("sentinel")
			}
			if len(f.Calls()) != 1 {
				t.Fatal("retried")
			}
		})
	}

	t.Run("bodies that are not the API error shape", func(t *testing.T) {
		f := newFakeAPI(t, rawReply(502, "<html>bad gateway</html>"), rawReply(400, "null"), rawReply(401, `{"error":"invalid_api_key","message":"flat"}`), rawReply(404, `{"error":{"code":1,"message":null}}`))
		c, _ := testClient(t, f, WithMaxRetries(0))
		for _, want := range []struct {
			status int
			kind   Kind
		}{{502, KindAPI}, {400, KindValidation}, {401, KindAuthentication}, {404, KindNotFound}} {
			_, err := c.Apps.Get(context.Background(), "a")
			var e *Error
			errors.As(err, &e)
			if e.Status != want.status || e.Kind != want.kind || e.Code != "" || e.Message != "HTTP "+strconv.Itoa(want.status) {
				t.Fatalf("%+v", e)
			}
		}
	})

	t.Run("invalid json in 2xx is not retried", func(t *testing.T) {
		f := newFakeAPI(t, rawReply(200, "{oops"))
		c, _ := testClient(t, f)
		_, err := c.Apps.Get(context.Background(), "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindAPI || e.Status != 200 || !strings.Contains(e.Message, "Invalid JSON") || len(f.Calls()) != 1 {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("json of the wrong shape in 2xx", func(t *testing.T) {
		f := newFakeAPI(t, rawReply(200, `{"id": 1}`))
		c, _ := testClient(t, f)
		_, err := c.Apps.Get(context.Background(), "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindAPI || !strings.Contains(e.Message, "Unexpected response") || e.Unwrap() == nil {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("empty 2xx body", func(t *testing.T) {
		f := newFakeAPI(t, rawReply(200, ""))
		c, _ := testClient(t, f)
		r, err := c.Users.Delete(context.Background(), "u1")
		if err != nil || r.EndUserID != "" {
			t.Fatal(r, err)
		}
	})

	t.Run("connection error keeps the cause", func(t *testing.T) {
		f := newFakeAPI(t, dropReply)
		c, _ := testClient(t, f, WithMaxRetries(0))
		_, err := c.Apps.Get(context.Background(), "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindConnection || e.Status != 0 || e.Err == nil || !strings.HasPrefix(e.Message, "Connection error: ") {
			t.Fatalf("%+v", e)
		}
		if !errors.Is(err, ErrConnection) || errors.Is(err, ErrTimeout) {
			t.Fatal("sentinel")
		}
	})

	t.Run("unencodable body", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{}))
		c, _ := testClient(t, f)
		_, err := c.Register.Verify(context.Background(), &RegisterVerifyParams{ChallengeID: "c", Response: json.RawMessage(`{bad`)})
		if !errors.Is(err, ErrInvalidArgument) || len(f.Calls()) != 0 {
			t.Fatal(err)
		}
	})

	t.Run("invalid base url", func(t *testing.T) {
		c, _ := NewClient("sk_test_x", WithBaseURL("http://bad host"))
		_, err := c.Apps.Get(context.Background(), "a")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatal(err)
		}
	})
}

func TestRetries(t *testing.T) {
	ctx := context.Background()
	verify := func(c *Client) error {
		_, err := c.Login.Verify(ctx, &LoginVerifyParams{ChallengeID: "c", Response: json.RawMessage(`{}`)})
		return err
	}
	getApp := func(c *Client) error { _, err := c.Apps.Get(ctx, "a"); return err }
	cases := []struct {
		name      string
		replies   []reply
		opts      []Option
		op        func(c *Client) error
		calls     int
		sleeps    []time.Duration
		wantError error
	}{
		{
			name:    "5xx with backoff, then success",
			replies: []reply{apiError(500, "internal_error", "x"), jsonReply(503, map[string]any{}), jsonReply(200, app)},
			op:      getApp,
			calls:   3, sleeps: []time.Duration{500 * time.Millisecond, time.Second},
		},
		{
			name:    "gives up after max retries",
			replies: []reply{apiError(500, "internal_error", "down")},
			opts:    []Option{WithMaxRetries(3)},
			op:      getApp,
			calls:   4, sleeps: []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second}, wantError: ErrAPI,
		},
		{
			name:    "max retries per request",
			replies: []reply{jsonReply(500, map[string]any{})},
			opts:    []Option{WithMaxRetries(5)},
			op:      func(c *Client) error { _, err := c.Apps.Get(ctx, "a", WithRequestMaxRetries(0)); return err },
			calls:   1, wantError: ErrAPI,
		},
		{
			name:    "connection errors retried for safe requests",
			replies: []reply{dropReply, jsonReply(200, app)},
			op:      getApp,
			calls:   2, sleeps: []time.Duration{500 * time.Millisecond},
		},
		{
			name:    "PATCH and DELETE are retried",
			replies: []reply{jsonReply(502, map[string]any{}), jsonReply(200, map[string]any{"id": "crd_1"}), jsonReply(502, map[string]any{}), jsonReply(200, map[string]any{})},
			op: func(c *Client) error {
				if _, err := c.Credentials.Rename(ctx, "crd_1", &CredentialRenameParams{Name: "x"}); err != nil {
					return err
				}
				_, err := c.Credentials.Revoke(ctx, "crd_1")
				return err
			},
			calls: 4, sleeps: []time.Duration{500 * time.Millisecond, 500 * time.Millisecond},
		},
		{
			name:    "4xx not retried",
			replies: []reply{apiError(410, "challenge_expired", "x")},
			op:      verify,
			calls:   1, wantError: ErrChallengeExpired,
		},
		{
			name:    "429 waits retry-after, for any request",
			replies: []reply{apiError(429, "rate_limited", "slow", "retry-after", "7"), jsonReply(200, map[string]any{"end_user_id": "eu_1"})},
			op:      verify,
			calls:   2, sleeps: []time.Duration{7 * time.Second},
		},
		{
			name:    "429 without retry-after uses backoff",
			replies: []reply{apiError(429, "rate_limited", "x"), jsonReply(200, app)},
			op:      getApp,
			calls:   2, sleeps: []time.Duration{500 * time.Millisecond},
		},
		{
			name:    "429 at exactly one minute is retried",
			replies: []reply{jsonReply(429, map[string]any{}, "retry-after", "60"), jsonReply(200, app)},
			op:      getApp,
			calls:   2, sleeps: []time.Duration{time.Minute},
		},
		{
			name:    "429 longer than a minute returned at once",
			replies: []reply{apiError(429, "rate_limited", "x", "retry-after", "61")},
			op:      getApp,
			calls:   1, wantError: ErrRateLimit,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAPI(t, tc.replies...)
			c, s := testClient(t, f, tc.opts...)
			err := tc.op(c)
			if tc.wantError == nil && err != nil {
				t.Fatal(err)
			}
			if tc.wantError != nil && !errors.Is(err, tc.wantError) {
				t.Fatalf("got %v, want %v", err, tc.wantError)
			}
			if n := len(f.Calls()); n != tc.calls {
				t.Fatalf("calls = %d, want %d", n, tc.calls)
			}
			if got := s.All(); !reflect.DeepEqual(got, tc.sleeps) && !(len(got) == 0 && len(tc.sleeps) == 0) {
				t.Fatalf("sleeps = %v, want %v", got, tc.sleeps)
			}
		})
	}

	t.Run("429 returned with RetryAfter", func(t *testing.T) {
		f := newFakeAPI(t, apiError(429, "rate_limited", "x", "retry-after", "1"))
		c, _ := testClient(t, f, WithMaxRetries(1))
		_, err := c.Apps.Get(ctx, "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindRateLimit || e.Code != "rate_limited" || e.RetryAfter == nil || *e.RetryAfter != time.Second || len(f.Calls()) != 2 {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("POST is not retried on 5xx, connection errors or timeouts", func(t *testing.T) {
		raw := json.RawMessage(`{}`)
		for _, rep := range []reply{jsonReply(500, map[string]any{}), dropReply, hangReply} {
			f := newFakeAPI(t, rep)
			c, _ := testClient(t, f, WithTimeout(50*time.Millisecond))
			ops := []func() error{
				func() error {
					_, err := c.Register.Options(ctx, &RegisterOptionsParams{ExternalID: "u", DisplayName: "d"})
					return err
				},
				func() error {
					_, err := c.Register.Verify(ctx, &RegisterVerifyParams{ChallengeID: "c", Response: raw})
					return err
				},
				func() error { _, err := c.Login.Options(ctx, nil); return err },
				func() error { return verify(c) },
				func() error { _, err := c.Users.Revoke(ctx, "u"); return err },
				func() error { _, err := c.Recovery.Start(ctx, &RecoveryStartParams{ExternalID: "u"}); return err },
			}
			for _, op := range ops {
				var e *Error
				if !errors.As(op(), &e) {
					t.Fatal("no error")
				}
			}
			if len(f.Calls()) != len(ops) {
				t.Fatalf("calls = %d", len(f.Calls()))
			}
		}
	})
}

func TestTimeoutAndCancel(t *testing.T) {
	t.Run("each attempt times out; safe requests are retried", func(t *testing.T) {
		f := newFakeAPI(t, hangReply)
		c, _ := testClient(t, f, WithTimeout(50*time.Millisecond), WithMaxRetries(1))
		_, err := c.Apps.Get(context.Background(), "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindTimeout || !errors.Is(err, ErrTimeout) || !errors.Is(err, ErrConnection) || e.Message != "Request timed out after 50ms" {
			t.Fatalf("%+v", e)
		}
		if len(f.Calls()) != 2 {
			t.Fatal(len(f.Calls()))
		}
	})

	t.Run("timeout per request", func(t *testing.T) {
		f := newFakeAPI(t, hangReply)
		c, _ := testClient(t, f, WithTimeout(time.Minute))
		_, err := c.Recovery.Start(context.Background(), &RecoveryStartParams{ExternalID: "u"}, WithRequestTimeout(20*time.Millisecond))
		if !errors.Is(err, ErrTimeout) || len(f.Calls()) != 1 {
			t.Fatal(err)
		}
	})

	t.Run("http.Client timeout counts as a timeout", func(t *testing.T) {
		f := newFakeAPI(t, hangReply)
		c, _ := testClient(t, f, WithHTTPClient(&http.Client{Timeout: 20 * time.Millisecond}), WithMaxRetries(0))
		_, err := c.Apps.Get(context.Background(), "a")
		if !errors.Is(err, ErrTimeout) {
			t.Fatal(err)
		}
	})

	t.Run("a cancelled context stops the request and is not retried", func(t *testing.T) {
		f := newFakeAPI(t, hangReply)
		c, _ := testClient(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		_, err := c.Apps.Get(ctx, "a")
		var e *Error
		errors.As(err, &e)
		if e.Kind != KindConnection || e.Message != "Request was aborted" || len(f.Calls()) != 1 {
			t.Fatalf("%+v", e)
		}
	})

	t.Run("a context cancelled before the call sends nothing", func(t *testing.T) {
		f := newFakeAPI(t, hangReply)
		c, _ := testClient(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := c.Apps.Get(ctx, "a")
		if !errors.Is(err, ErrConnection) || !errors.Is(err, context.Canceled) || len(f.Calls()) != 0 {
			t.Fatal(err)
		}
	})

	t.Run("cancelling during the wait between retries", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(503, map[string]any{}))
		c, _ := testClient(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		c.sleep = func(context.Context, time.Duration) error { cancel(); return context.Canceled }
		_, err := c.Apps.Get(ctx, "a")
		if !errors.Is(err, ErrConnection) || !errors.Is(err, context.Canceled) || len(f.Calls()) != 1 {
			t.Fatal(err)
		}
	})

	t.Run("real sleep honours the context", func(t *testing.T) {
		if err := sleepContext(context.Background(), time.Millisecond); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
}

func TestHelpers(t *testing.T) {
	half := func() float64 { return 0.5 }
	var got []time.Duration
	for _, n := range []int{0, 1, 2, 3, 4, 5, 10} {
		got = append(got, backoff(n, half))
	}
	ms := time.Millisecond
	if !reflect.DeepEqual(got, []time.Duration{500 * ms, 1000 * ms, 2000 * ms, 4000 * ms, 8000 * ms, 8000 * ms, 8000 * ms}) {
		t.Fatal(got)
	}
	if backoff(0, func() float64 { return 0 }) != 375*ms || backoff(0, func() float64 { return 1 }) != 625*ms {
		t.Fatal("jitter")
	}

	h := func(kv ...string) http.Header {
		out := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			out.Set(kv[i], kv[i+1])
		}
		return out
	}
	at := func(sec float64) time.Time { return time.Unix(0, int64(sec*1e9)) }
	cases := []struct {
		h    http.Header
		now  float64
		want time.Duration
		ok   bool
	}{
		{h("retry-after", "2"), 0, 2 * time.Second, true},
		{h("retry-after", "0.4"), 0, 400 * ms, true},
		{h("retry-after", "Thu, 01 Jan 1970 00:00:05 GMT"), 1, 4 * time.Second, true},
		{h("retry-after", "Thu, 01 Jan 1970 00:00:05 GMT"), 9, 0, true},
		{h("retry-after", "soon"), 4, 0, false},
		{h("retry-after", "-3"), 0, 0, true},
		{h("retry-after", "NaN"), 0, 0, false},
		{h("retry-after", " "), 0, 0, false},
		{h(), 0, 0, false},
	}
	for i, tc := range cases {
		d, ok := rateLimitWait(tc.h, at(tc.now))
		if d != tc.want || ok != tc.ok {
			t.Errorf("case %d: got %v %v, want %v %v", i, d, ok, tc.want, tc.ok)
		}
	}
	if MaxRateLimitWait != time.Minute {
		t.Fatal(MaxRateLimitWait)
	}
	if *String("a") != "a" || !*Bool(true) {
		t.Fatal("pointer helpers")
	}
	e := &Error{Kind: KindRateLimit, Message: "slow"}
	if e.Error() != "slow" || e.Unwrap() != nil || e.RetryAfter != nil {
		t.Fatal(e)
	}
}
