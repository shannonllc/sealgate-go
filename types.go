package sealgate

import (
	"encoding/json"
	"time"
)

// Inputs and results of /v1 (as in the API reference at https://sealgate.jp/docs). Times are ISO 8601 strings.

// RegisterOptionsParams starts a registration.
type RegisterOptionsParams struct {
	// ExternalID is your user ID (up to 200 characters). Prefer an ID that does not identify a person.
	ExternalID string `json:"external_id"`
	// DisplayName is shown in the authenticator dialog (up to 64 characters).
	DisplayName string `json:"display_name"`
	// SignedIn is true when adding a passkey for a user who already has one. Decide it from your server's
	// session, never from a value the browser sent.
	SignedIn *bool `json:"signed_in,omitempty"`
	// RecoveryToken is a token from Recovery.Start, for a user who lost their device.
	RecoveryToken string `json:"recovery_token,omitempty"`
}

// RegisterOptions is the start of a registration. Return it to the browser SDK as is.
type RegisterOptions struct {
	// ChallengeID is passed to Register.Verify. Single use, expires in 5 minutes.
	ChallengeID string `json:"challenge_id"`
	EndUserID   string `json:"end_user_id"`
	// Options is WebAuthn PublicKeyCredentialCreationOptions as JSON. Hand it to the browser SDK unchanged.
	Options json.RawMessage `json:"options"`
}

// RegisterVerifyParams finishes a registration.
type RegisterVerifyParams struct {
	ChallengeID string `json:"challenge_id"`
	// Response is the RegistrationResponseJSON from the browser, as is.
	Response json.RawMessage `json:"response"`
	// Name is the device name (up to 64 characters; longer names are cut).
	Name string `json:"name,omitempty"`
}

// RegisterResult is a saved passkey.
type RegisterResult struct {
	CredentialID string `json:"credential_id"`
	EndUserID    string `json:"end_user_id"`
}

// LoginOptionsParams starts a login.
type LoginOptionsParams struct {
	// ExternalID allows only this user's passkeys. Leave it empty to let the user pick a passkey on the device.
	ExternalID string `json:"external_id,omitempty"`
}

// LoginOptions is the start of a login. Return it to the browser SDK as is.
type LoginOptions struct {
	// ChallengeID is passed to Login.Verify. Single use, expires in 5 minutes.
	ChallengeID string `json:"challenge_id"`
	// Options is WebAuthn PublicKeyCredentialRequestOptions as JSON. Hand it to the browser SDK unchanged.
	Options json.RawMessage `json:"options"`
}

// LoginVerifyParams finishes a login.
type LoginVerifyParams struct {
	ChallengeID string `json:"challenge_id"`
	// Response is the AuthenticationResponseJSON from the browser, as is.
	Response json.RawMessage `json:"response"`
}

// LoginResult is the user who logged in. Start your own session for ExternalID.
type LoginResult struct {
	EndUserID    string `json:"end_user_id"`
	ExternalID   string `json:"external_id"`
	CredentialID string `json:"credential_id"`
	UserVerified bool   `json:"user_verified"`
	// PasswordAllowed is false after the app's password_coexist_until.
	PasswordAllowed bool `json:"password_allowed"`
}

// Credential is a passkey.
type Credential struct {
	ID         string   `json:"id"`
	Name       *string  `json:"name"`
	Transports []string `json:"transports"`
	// AAGUID is as reported by the authenticator; not verified.
	AAGUID         *string `json:"aaguid"`
	BackupEligible bool    `json:"backup_eligible"`
	BackedUp       bool    `json:"backed_up"`
	CreatedAt      string  `json:"created_at"`
	LastUsedAt     *string `json:"last_used_at"`
	RevokedAt      *string `json:"revoked_at"`
}

// CredentialList is a user's passkeys, revoked ones included.
type CredentialList struct {
	EndUserID string       `json:"end_user_id"`
	Data      []Credential `json:"data"`
}

// CredentialRenameParams renames a passkey.
type CredentialRenameParams struct {
	// Name is 1 to 64 characters. Surrounding spaces and control characters are removed.
	Name string `json:"name"`
}

// CredentialRevokeResult is a revoked passkey.
type CredentialRevokeResult struct {
	CredentialID string  `json:"credential_id"`
	RevokedAt    *string `json:"revoked_at"`
}

// UserRevokeResult is the result of revoking all of a user's passkeys.
type UserRevokeResult struct {
	EndUserID string `json:"end_user_id"`
	Revoked   int    `json:"revoked"`
}

// UserDeleteResult is the result of deleting a user.
type UserDeleteResult struct {
	EndUserID          string `json:"end_user_id"`
	Deleted            bool   `json:"deleted"`
	CredentialsDeleted int    `json:"credentials_deleted"`
}

// RecoveryStartParams issues a recovery token.
type RecoveryStartParams struct {
	ExternalID string `json:"external_id"`
	// Reason is kept in the audit log (up to 200 characters).
	Reason string `json:"reason,omitempty"`
}

// RecoveryToken is passed to Register.Options as RecoveryToken. Valid for 15 minutes, single use.
type RecoveryToken struct {
	RecoveryToken string `json:"recovery_token"`
	ExpiresAt     string `json:"expires_at"`
}

// App is the API key's app (environment).
type App struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	RPID                 string   `json:"rp_id"`
	RPName               string   `json:"rp_name"`
	Origins              []string `json:"origins"`
	ResidentKey          string   `json:"resident_key"`
	UserVerification     string   `json:"user_verification"`
	PasswordCoexistUntil *string  `json:"password_coexist_until"`
	WebhookURL           *string  `json:"webhook_url"`
}

// AppUpdateParams changes the only two settings an API key can change. Set one or both.
type AppUpdateParams struct {
	// ResidentKey is required, preferred or discouraged.
	ResidentKey string `json:"resident_key,omitempty"`
	// UserVerification is required or preferred.
	UserVerification string `json:"user_verification,omitempty"`
}

// AuditListParams narrows the audit log.
type AuditListParams struct {
	// Event is one event, such as "login.failed".
	Event string
	// Since keeps entries at or after this time. Zero means no limit.
	Since time.Time
	// Limit is the number of entries (default 200, up to 1000). 0 uses the default.
	Limit int
}

// AuditEntry is one audit log entry.
type AuditEntry struct {
	ID           string  `json:"id"`
	Event        string  `json:"event"`
	OK           bool    `json:"ok"`
	EndUserID    *string `json:"end_user_id"`
	CredentialID *string `json:"credential_id"`
	// IP and UserAgent are of the request SealGate received: your server for API calls, not the user's device.
	IP        *string         `json:"ip"`
	UserAgent *string         `json:"user_agent"`
	Detail    json.RawMessage `json:"detail"`
	At        string          `json:"at"`
}

// AuditList is newest first. The API returns one list (no further pages); narrow it with Since and Limit.
type AuditList struct {
	Data []AuditEntry `json:"data"`
}

// Stats are the app's numbers.
type Stats struct {
	// MAU is for the last 6 months (UTC calendar months, oldest first; this month so far).
	MAU []struct {
		Month string `json:"month"`
		Users int    `json:"users"`
	} `json:"mau"`
	Registrations []struct {
		Month string `json:"month"`
		Count int    `json:"count"`
	} `json:"registrations"`
	// Logins is for the last 30 days.
	Logins struct {
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	} `json:"logins"`
	Users struct {
		Total       int `json:"total"`
		WithPasskey int `json:"with_passkey"`
	} `json:"users"`
	// Transports counts active passkeys by transport, most first ("unknown" when none was reported).
	Transports []struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	} `json:"transports"`
}
