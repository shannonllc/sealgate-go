package sealgate

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Verifying webhooks on the receiving side (Standard Webhooks).
//   webhook-id / webhook-timestamp (seconds) / webhook-signature: "v1,<base64>" (several, space-separated, during a rotation)
// The signed content is "{id}.{timestamp}.{body}"; the key is the base64-decoded part after "whsec_".

const secretPrefix = "whsec_"

// DefaultTolerance is the allowed clock difference, both ways.
const DefaultTolerance = 5 * time.Minute

const maxSafeInteger = 1<<53 - 1

var digits = regexp.MustCompile(`^[0-9]+$`)

// Webhook verifies webhooks signed in the Standard Webhooks format. Most code can use [VerifyWebhook] instead.
type Webhook struct {
	keys      [][]byte
	tolerance time.Duration
	now       func() time.Time
}

// WebhookOption configures a [Webhook].
type WebhookOption func(*webhookConfig)

type webhookConfig struct {
	tolerance time.Duration
	more      []string
}

// WithTolerance sets the allowed clock difference, both ways. Default 5 minutes.
func WithTolerance(d time.Duration) WebhookOption { return func(w *webhookConfig) { w.tolerance = d } }

// WithSecrets adds secrets that also verify, while you switch to a new secret.
func WithSecrets(secrets ...string) WebhookOption {
	return func(w *webhookConfig) { w.more = append(w.more, secrets...) }
}

func decodeBase64(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

func keyOf(secret string) ([]byte, error) {
	if secret == "" {
		return nil, newError(KindInvalidArgument, "Webhook secret is required", nil)
	}
	key, err := decodeBase64(strings.TrimPrefix(secret, secretPrefix))
	if err != nil {
		return nil, newError(KindInvalidArgument, "Webhook secret is not valid base64 (expected whsec_…)", err)
	}
	return key, nil
}

// NewWebhook creates a verifier. secret is the signing secret (whsec_…) shown under the environment settings'
// delivery log and signing key. Pass WithSecrets while you switch to a new secret.
func NewWebhook(secret string, opts ...WebhookOption) (*Webhook, error) {
	cfg := webhookConfig{tolerance: DefaultTolerance}
	for _, o := range opts {
		o(&cfg)
	}
	w := &Webhook{tolerance: cfg.tolerance, now: time.Now}
	for _, s := range append([]string{secret}, cfg.more...) {
		key, err := keyOf(s)
		if err != nil {
			return nil, err
		}
		w.keys = append(w.keys, key)
	}
	return w, nil
}

func headerValue(h http.Header, name string) string {
	if v := h.Get(name); v != "" {
		return v
	}
	// headers built with lowercase keys without Set (map literals)
	for k, vs := range h {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func mac(key []byte, msgID, timestamp string, payload []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msgID + "." + timestamp + "."))
	m.Write(payload)
	return m.Sum(nil)
}

func verificationError(message string, cause error) *Error {
	return newError(KindWebhookVerification, message, cause)
}

// Verify checks the signature and timestamp, then returns the raw body. payload is the raw request body, exactly as
// received. The error matches ErrWebhookVerification when verification fails or the body is not JSON.
func (w *Webhook) Verify(payload []byte, headers http.Header) (json.RawMessage, error) {
	msgID := headerValue(headers, "webhook-id")
	timestamp := headerValue(headers, "webhook-timestamp")
	signature := headerValue(headers, "webhook-signature")
	if msgID == "" || timestamp == "" || signature == "" {
		return nil, verificationError("Missing required headers", nil)
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if !digits.MatchString(timestamp) || err != nil || ts > maxSafeInteger {
		return nil, verificationError("Invalid webhook-timestamp header", nil)
	}
	now := w.now().Unix()
	tol := int64(w.tolerance / time.Second)
	if now-ts > tol {
		return nil, verificationError("Message timestamp too old", nil)
	}
	if ts-now > tol {
		return nil, verificationError("Message timestamp too new", nil)
	}

	expected := make([][]byte, len(w.keys))
	for i, key := range w.keys {
		expected[i] = mac(key, msgID, timestamp, payload)
	}
	for _, part := range strings.Split(signature, " ") {
		version, sig, ok := strings.Cut(part, ",")
		if !ok || version != "v1" || sig == "" {
			continue
		}
		given, err := decodeBase64(sig)
		if err != nil {
			continue
		}
		for _, e := range expected {
			if hmac.Equal(given, e) {
				if !json.Valid(payload) {
					return nil, verificationError("Payload is not valid JSON", nil)
				}
				return append(json.RawMessage(nil), payload...), nil
			}
		}
	}
	return nil, verificationError("No matching signature found", nil)
}

// Sign computes the webhook-signature value ("v1,<base64>") with the first secret. Useful for tests.
func (w *Webhook) Sign(msgID string, timestamp time.Time, payload []byte) string {
	return "v1," + base64.StdEncoding.EncodeToString(mac(w.keys[0], msgID, strconv.FormatInt(timestamp.Unix(), 10), payload))
}

// isObject reports whether raw is a JSON object (not an array, a string or null).
func isObject(raw json.RawMessage) bool {
	t := bytes.TrimLeft(raw, " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

// VerifyEvent verifies a webhook sent by SealGate and returns the event. See [VerifyWebhook].
func (w *Webhook) VerifyEvent(payload []byte, headers http.Header) (*Event, error) {
	body, err := w.Verify(payload, headers)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(body, &fields) // not an object leaves it nil
	t, ok := jsonString(fields["type"])
	data := fields["data"]
	if !isObject(body) || !ok || !isObject(data) {
		return nil, verificationError("Payload is not a SealGate event ({ type, timestamp, data })", nil)
	}
	ev := &Event{Type: EventType(t), Data: data, Raw: body}
	ev.Timestamp, _ = jsonString(fields["timestamp"])
	return ev, nil
}

// VerifyWebhook verifies a webhook sent by SealGate (login.succeeded, credential.revoked and others) and returns
// the event. Use [Event.ParseData] for the data. payload is the raw request body, exactly as received. secret is the
// signing secret (whsec_…); pass WithSecrets while you switch to a new one. The error matches
// ErrWebhookVerification when verification fails, and ErrInvalidArgument when the secret is invalid.
func VerifyWebhook(payload []byte, headers http.Header, secret string, opts ...WebhookOption) (*Event, error) {
	w, err := NewWebhook(secret, opts...)
	if err != nil {
		return nil, err
	}
	return w.VerifyEvent(payload, headers)
}
