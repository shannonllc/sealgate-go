package sealgate

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Kind classifies an [Error].
type Kind string

// Error kinds. Match them with errors.Is and the Err… sentinels, or read [Error.Kind].
const (
	// KindValidation is 400 invalid_request: a parameter is missing or malformed.
	KindValidation Kind = "validation"
	// KindAuthentication is 401 invalid_api_key: the API key is missing, wrong or revoked.
	KindAuthentication Kind = "authentication"
	// KindVerification is 401 verification_failed: the passkey response did not verify.
	KindVerification Kind = "verification"
	// KindPaymentRequired is 402 mau_limit: an organization without a payment method reached the monthly MAU limit.
	KindPaymentRequired Kind = "payment_required"
	// KindPermission is 403: credential_revoked, origin_not_allowed or recovery_not_allowed. See Code.
	KindPermission Kind = "permission"
	// KindNotFound is 404 not_found: the user, passkey or app does not exist for this API key.
	KindNotFound Kind = "not_found"
	// KindChallengeExpired is 410 challenge_expired: the challenge expired (5 minutes), was used, or is unknown.
	KindChallengeExpired Kind = "challenge_expired"
	// KindRateLimit is 429 rate_limited: too many requests, returned after retries are used up.
	KindRateLimit Kind = "rate_limit"
	// KindAPI is any other error response, including 5xx (internal_error).
	KindAPI Kind = "api"
	// KindConnection means the request could not reach the API (DNS, TCP, TLS) or was cancelled.
	KindConnection Kind = "connection"
	// KindTimeout means the request did not complete within the timeout. It also matches ErrConnection.
	KindTimeout Kind = "timeout"
	// KindWebhookVerification means signature verification of an incoming webhook failed.
	KindWebhookVerification Kind = "webhook_verification"
	// KindInvalidArgument is a usage error, such as a missing API key or an invalid webhook secret.
	KindInvalidArgument Kind = "invalid_argument"
)

// Sentinels for errors.Is.
var (
	ErrValidation          = errors.New("sealgate: validation error")
	ErrAuthentication      = errors.New("sealgate: authentication error")
	ErrVerification        = errors.New("sealgate: passkey verification failed")
	ErrPaymentRequired     = errors.New("sealgate: payment required")
	ErrPermission          = errors.New("sealgate: permission error")
	ErrNotFound            = errors.New("sealgate: not found")
	ErrChallengeExpired    = errors.New("sealgate: challenge expired")
	ErrRateLimit           = errors.New("sealgate: rate limited")
	ErrAPI                 = errors.New("sealgate: api error")
	ErrConnection          = errors.New("sealgate: connection error")
	ErrTimeout             = errors.New("sealgate: timeout")
	ErrWebhookVerification = errors.New("sealgate: webhook verification failed")
	ErrInvalidArgument     = errors.New("sealgate: invalid argument")
)

var sentinels = map[Kind]error{
	KindValidation:          ErrValidation,
	KindAuthentication:      ErrAuthentication,
	KindVerification:        ErrVerification,
	KindPaymentRequired:     ErrPaymentRequired,
	KindPermission:          ErrPermission,
	KindNotFound:            ErrNotFound,
	KindChallengeExpired:    ErrChallengeExpired,
	KindRateLimit:           ErrRateLimit,
	KindAPI:                 ErrAPI,
	KindConnection:          ErrConnection,
	KindTimeout:             ErrTimeout,
	KindWebhookVerification: ErrWebhookVerification,
	KindInvalidArgument:     ErrInvalidArgument,
}

// Error is every error returned by the SDK. Use errors.As to read it, or errors.Is with a sentinel:
//
//	var e *sealgate.Error
//	if errors.As(err, &e) { fmt.Println(e.Status, e.Code) }
//	if errors.Is(err, sealgate.ErrChallengeExpired) { … }
type Error struct {
	Kind Kind
	// Message from the API, or a description of the failure.
	Message string
	// Status is the HTTP status. 0 when no response was received.
	Status int
	// Code is the API error code, such as "invalid_request", "credential_revoked" or "challenge_expired".
	Code string
	// RetryAfter is the wait from retry-after on a 429, or nil.
	RetryAfter *time.Duration
	// Err is the underlying cause, if any.
	Err error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.Err }

// Is reports whether target is the sentinel for e's kind. A timeout also matches ErrConnection.
func (e *Error) Is(target error) bool {
	if target == sentinels[e.Kind] {
		return true
	}
	return e.Kind == KindTimeout && target == ErrConnection
}

func newError(kind Kind, message string, cause error) *Error {
	return &Error{Kind: kind, Message: message, Err: cause}
}

// parseRetryAfter returns the wait from retry-after (seconds or HTTP date).
func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	if strings.TrimSpace(value) == "" {
		return 0, false
	}
	if n, err := strconv.ParseFloat(value, 64); err == nil {
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return time.Duration(math.Max(0, n) * float64(time.Second)), true
	}
	at, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	d := at.Sub(now)
	if d < 0 {
		d = 0
	}
	return d, true
}

// jsonString decodes raw when it is a JSON string (not null, a number or an object).
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// errorFromResponse builds the error for a non-2xx response ({ "error": { "code", "message" } }).
func errorFromResponse(status int, body []byte, h http.Header, now time.Time) *Error {
	var parsed struct {
		Error map[string]json.RawMessage `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed) // HTML from a proxy, empty body, other shapes etc. leave it empty
	e := &Error{Status: status, Message: fmt.Sprintf("HTTP %d", status)}
	if s, ok := jsonString(parsed.Error["code"]); ok {
		e.Code = s
	}
	if s, ok := jsonString(parsed.Error["message"]); ok {
		e.Message = s
	}
	switch status {
	case 400:
		e.Kind = KindValidation
	case 401:
		e.Kind = KindAuthentication
		if e.Code == "verification_failed" {
			e.Kind = KindVerification
		}
	case 402:
		e.Kind = KindPaymentRequired
	case 403:
		e.Kind = KindPermission
	case 404:
		e.Kind = KindNotFound
	case 410:
		e.Kind = KindChallengeExpired
	case 429:
		e.Kind = KindRateLimit
		if d, ok := parseRetryAfter(h.Get("retry-after"), now); ok {
			e.RetryAfter = &d
		}
	default:
		e.Kind = KindAPI
	}
	return e
}
