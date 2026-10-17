package sealgate

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The vectors are signed like SealGate, by hand and by the Node SDK, with results decided by the Node SDK.
// The same file is used by the Python and PHP SDKs.
type vector struct {
	Name      string            `json:"name"`
	Verify    string            `json:"verify"`
	Secret    json.RawMessage   `json:"secret"`
	Payload   string            `json:"payload"`
	Headers   map[string]string `json:"headers"`
	Now       int64             `json:"now"`
	Tolerance *int64            `json:"tolerance"`
	Expect    json.RawMessage   `json:"expect"`
	Error     string            `json:"error"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/webhook_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Vectors []vector }
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.Vectors
}

func (v vector) secrets() []string {
	var list []string
	if json.Unmarshal(v.Secret, &list) == nil {
		return list
	}
	var one string
	_ = json.Unmarshal(v.Secret, &one)
	return []string{one}
}

func (v vector) header() http.Header {
	h := http.Header{}
	for k, val := range v.Headers {
		h.Set(k, val)
	}
	return h
}

func (v vector) webhook(t *testing.T) *Webhook {
	t.Helper()
	s := v.secrets()
	opts := []WebhookOption{WithSecrets(s[1:]...)}
	if v.Tolerance != nil {
		opts = append(opts, WithTolerance(time.Duration(*v.Tolerance)*time.Second))
	}
	w, err := NewWebhook(s[0], opts...)
	if err != nil {
		t.Fatal(err)
	}
	w.now = func() time.Time { return time.Unix(v.Now, 0) }
	return w
}

func sameJSON(t *testing.T, got []byte, want json.RawMessage) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(want, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			w := v.webhook(t)
			var got []byte
			var err error
			switch v.Verify {
			case "webhook":
				var ev *Event
				if ev, err = w.VerifyEvent([]byte(v.Payload), v.header()); err == nil {
					got = ev.Raw
				}
			default:
				got, err = w.Verify([]byte(v.Payload), v.header())
			}
			if string(v.Expect) == "null" {
				var e *Error
				if !errors.As(err, &e) || e.Kind != KindWebhookVerification || e.Message != v.Error || !errors.Is(err, ErrWebhookVerification) {
					t.Fatalf("got %v, want %q", err, v.Error)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			sameJSON(t, got, v.Expect)
		})
	}
}

func find(t *testing.T, name string) vector {
	t.Helper()
	for _, v := range loadVectors(t) {
		if v.Name == name {
			return v
		}
	}
	t.Fatal("no vector", name)
	return vector{}
}

func TestSignMatchesTheSenderAndNode(t *testing.T) {
	for _, name := range []string{"signed like SealGate", "signed with an HMAC by hand", "signed by the node sdk", "standard webhooks spec vector"} {
		v := find(t, name)
		w, _ := NewWebhook(v.secrets()[0], WithSecrets("whsec_dGhpcyBpcyBhbm90aGVyIHNlY3JldCBrZXk="))
		ts, _ := strconv.ParseInt(v.Headers["webhook-timestamp"], 10, 64)
		if got := w.Sign(v.Headers["webhook-id"], time.Unix(ts, 0), []byte(v.Payload)); got != v.Headers["webhook-signature"] {
			t.Fatalf("%s: %s", name, got)
		}
	}
}

func TestEvent(t *testing.T) {
	v := find(t, "webhook event signed like SealGate")
	ev, err := v.webhook(t).VerifyEvent([]byte(v.Payload), v.header())
	if err != nil || ev.Type != EventLoginSucceeded || ev.Timestamp != "2026-09-22T00:00:00.000Z" {
		t.Fatal(ev, err)
	}
	d, err := ev.ParseData()
	if err != nil || d.AppID != "app_1" || d.ExternalID != "山田-123" || d.CredentialID != "crd_1" || d.Reason != nil {
		t.Fatal(d, err)
	}
	var m map[string]any
	if err := ev.UnmarshalData(&m); err != nil || m["end_user_id"] != "eu_1" {
		t.Fatal(m, err)
	}
	if _, err := (&Event{Data: json.RawMessage(`[]`)}).ParseData(); err == nil {
		t.Fatal("decoded an array")
	}
	r, _ := (&Event{Data: json.RawMessage(`{"app_id":"a","external_id":"u","reason":"desk"}`)}).ParseData()
	if *r.Reason != "desk" {
		t.Fatal(r)
	}
}

func TestVerifyWebhookFunction(t *testing.T) {
	const secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
	const other = "whsec_dGhpcyBpcyBhbm90aGVyIHNlY3JldCBrZXk="
	w, _ := NewWebhook(secret)
	now := time.Now()
	sign := func(body string) http.Header {
		h := http.Header{}
		h.Set("webhook-id", "msg_now")
		h.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
		h.Set("webhook-signature", w.Sign("msg_now", now, []byte(body)))
		return h
	}
	ev := `{"type":"user.deleted","timestamp":"t","data":{"app_id":"app_1","end_user_id":"eu_1","credentials_deleted":2}}`
	e, err := VerifyWebhook([]byte(ev), sign(ev), other, WithSecrets(secret), WithTolerance(10*time.Second))
	if err != nil || e.Type != EventUserDeleted {
		t.Fatal(e, err)
	}
	if d, _ := e.ParseData(); d.CredentialsDeleted != 2 {
		t.Fatal(d)
	}
	if _, err := VerifyWebhook([]byte(ev), sign(ev), "whsec_***"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	if _, err := VerifyWebhook([]byte(ev), http.Header{}, secret); !errors.Is(err, ErrWebhookVerification) {
		t.Fatal(err)
	}
}

func TestHeaderForms(t *testing.T) {
	v := find(t, "signed like SealGate")
	w := v.webhook(t)
	// a map literal with lowercase keys (not canonicalised by Set)
	lower := http.Header{}
	for k, val := range v.Headers {
		lower[k] = []string{val, "x"}
	}
	got, err := w.Verify([]byte(v.Payload), lower)
	if err != nil {
		t.Fatal(err)
	}
	sameJSON(t, got, v.Expect)
	empty := http.Header{"webhook-id": {}}
	if _, err := w.Verify([]byte(v.Payload), empty); err == nil || !strings.Contains(err.Error(), "Missing required headers") {
		t.Fatal(err)
	}
}

func TestSecretChecks(t *testing.T) {
	if _, err := NewWebhook(""); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "required") {
		t.Fatal(err)
	}
	if _, err := NewWebhook("whsec_***"); !errors.Is(err, ErrInvalidArgument) || !strings.Contains(err.Error(), "not valid base64") {
		t.Fatal(err)
	}
	if _, err := NewWebhook("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", WithSecrets("")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatal(err)
	}
	// unpadded base64 is accepted, like atob in the Node SDK
	w, err := NewWebhook("whsec_dGhpcyBpcyBhbm90aGVyIHNlY3JldCBrZXk")
	if err != nil || w.tolerance != DefaultTolerance || len(w.keys) != 1 {
		t.Fatal(err)
	}
}
