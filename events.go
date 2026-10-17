package sealgate

import "encoding/json"

// Webhooks sent by SealGate (Standard Webhooks body {type, timestamp, data}).

// EventType is the type of a webhook sent by SealGate.
type EventType string

// Event types.
const (
	EventRegisterCompleted EventType = "register.completed"
	EventRegisterFailed    EventType = "register.failed"
	EventLoginSucceeded    EventType = "login.succeeded"
	EventLoginFailed       EventType = "login.failed"
	EventCredentialRevoked EventType = "credential.revoked"
	EventCredentialRenamed EventType = "credential.renamed"
	EventUserRevoked       EventType = "user.revoked"
	EventUserDeleted       EventType = "user.deleted"
	EventRecoveryIssued    EventType = "recovery.issued"
)

// Event is a webhook sent by SealGate. Use the webhook-id header to spot redeliveries.
type Event struct {
	Type EventType
	// Timestamp is ISO 8601.
	Timestamp string
	// Data is the event's data. Use ParseData or UnmarshalData.
	Data json.RawMessage
	// Raw is the whole verified body.
	Raw json.RawMessage
}

// EventData holds the fields of every event's data. Which ones are set depends on Type:
//
//	register.completed  EndUserID, CredentialID
//	register.failed     Code
//	login.succeeded     EndUserID, ExternalID, CredentialID
//	login.failed        Code
//	credential.revoked  EndUserID, CredentialID
//	credential.renamed  EndUserID, CredentialID (the new name is not included)
//	user.revoked        EndUserID, Revoked
//	user.deleted        EndUserID, CredentialsDeleted
//	recovery.issued     ExternalID, Reason
type EventData struct {
	AppID        string `json:"app_id"`
	EndUserID    string `json:"end_user_id,omitempty"`
	ExternalID   string `json:"external_id,omitempty"`
	CredentialID string `json:"credential_id,omitempty"`
	// Code is the API error code for register.failed and login.failed, such as "verification_failed".
	Code string `json:"code,omitempty"`
	// Revoked is the number of passkeys revoked (user.revoked).
	Revoked int `json:"revoked,omitempty"`
	// CredentialsDeleted is the number of passkeys deleted (user.deleted).
	CredentialsDeleted int `json:"credentials_deleted,omitempty"`
	// Reason is the reason given to Recovery.Start, or nil (recovery.issued).
	Reason *string `json:"reason,omitempty"`
}

// UnmarshalData decodes Data into v.
func (e *Event) UnmarshalData(v any) error { return json.Unmarshal(e.Data, v) }

// ParseData decodes Data into an [EventData].
func (e *Event) ParseData() (*EventData, error) {
	d := &EventData{}
	if err := json.Unmarshal(e.Data, d); err != nil {
		return nil, err
	}
	return d, nil
}
