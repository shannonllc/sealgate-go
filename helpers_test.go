package sealgate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// call is one request the fake API received.
type call struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   map[string]any
	Raw    []byte
}

// reply writes one response. The last reply keeps being used.
type reply func(w http.ResponseWriter, r *http.Request)

func jsonReply(status int, body any, headers ...string) reply {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
}

func rawReply(status int, body string, headers ...string) reply {
	return func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i+1 < len(headers); i += 2 {
			w.Header().Set(headers[i], headers[i+1])
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// hangReply waits until the request is cancelled.
func hangReply(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }

// dropReply closes the connection without a response.
func dropReply(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("no hijacker")
	}
	conn, _, _ := hj.Hijack()
	conn.Close()
}

type fakeAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	replies []reply
	calls   []call
}

func newFakeAPI(t *testing.T, replies ...reply) *fakeAPI {
	t.Helper()
	f := &fakeAPI{replies: replies}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c := call{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Header: r.Header.Clone(), Raw: raw}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &c.Body)
		}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		rep := f.replies[0]
		if len(f.replies) > 1 {
			f.replies = f.replies[1:]
		}
		f.mu.Unlock()
		rep(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) Calls() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeAPI) Last() call {
	c := f.Calls()
	return c[len(c)-1]
}

// sleeps records the waits between retries instead of sleeping.
type sleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.d = append(s.d, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleeps) All() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.d...)
}

func testClient(t *testing.T, f *fakeAPI, opts ...Option) (*Client, *sleeps) {
	t.Helper()
	c, err := NewClient("sk_test_abc", append([]Option{WithBaseURL(f.srv.URL)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	s := &sleeps{}
	c.sleep = s.sleep
	c.random = func() float64 { return 0.5 }
	return c, s
}
