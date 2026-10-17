package sealgate

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

func esc(id string) string { return url.PathEscape(id) }

func get[T any](ctx context.Context, c *Client, path string, q url.Values, opts []RequestOption) (*T, error) {
	var out T
	if err := c.do(ctx, request{method: "GET", path: path, query: q, idempotent: true}, &out, c.config(opts)); err != nil {
		return nil, err
	}
	return &out, nil
}

func send[T any](ctx context.Context, c *Client, method, path string, body any, idempotent bool, opts []RequestOption) (*T, error) {
	var out T
	if err := c.do(ctx, request{method: method, path: path, body: body, idempotent: idempotent}, &out, c.config(opts)); err != nil {
		return nil, err
	}
	return &out, nil
}

// emptyObject is sent as {} for POST requests without parameters.
var emptyObject = struct{}{}

// RegisterService is passkey registration (/v1/register/*): start with Options, finish with Verify.
type RegisterService struct{ c *Client }

// Options starts a registration. Return the result to the browser SDK as is. A user who already has a passkey
// needs SignedIn or a RecoveryToken (403 recovery_not_allowed). Not retried on a 5xx or a connection error.
func (s *RegisterService) Options(ctx context.Context, p *RegisterOptionsParams, opts ...RequestOption) (*RegisterOptions, error) {
	return send[RegisterOptions](ctx, s.c, "POST", "/v1/register/options", p, false, opts)
}

// Verify checks the authenticator's response and saves the passkey. The challenge is single use, so this is not
// retried on a 5xx or a connection error.
func (s *RegisterService) Verify(ctx context.Context, p *RegisterVerifyParams, opts ...RequestOption) (*RegisterResult, error) {
	return send[RegisterResult](ctx, s.c, "POST", "/v1/register/verify", p, false, opts)
}

// LoginService is passkey login (/v1/login/*): start with Options, finish with Verify, then start your session.
type LoginService struct{ c *Client }

// Options starts a login. With nil params (or an empty ExternalID) the user picks a passkey saved on the device.
// Not retried on a 5xx or a connection error.
func (s *LoginService) Options(ctx context.Context, p *LoginOptionsParams, opts ...RequestOption) (*LoginOptions, error) {
	var body any = emptyObject
	if p != nil {
		body = p
	}
	return send[LoginOptions](ctx, s.c, "POST", "/v1/login/options", body, false, opts)
}

// Verify checks the signature and returns the user. Not retried on a 5xx or a connection error.
func (s *LoginService) Verify(ctx context.Context, p *LoginVerifyParams, opts ...RequestOption) (*LoginResult, error) {
	return send[LoginResult](ctx, s.c, "POST", "/v1/login/verify", p, false, opts)
}

// UsersService is users by your external_id (/v1/users/:external_id).
type UsersService struct{ c *Client }

// ListCredentials lists the user's passkeys, revoked ones included (RevokedAt).
func (s *UsersService) ListCredentials(ctx context.Context, externalID string, opts ...RequestOption) (*CredentialList, error) {
	return get[CredentialList](ctx, s.c, "/v1/users/"+esc(externalID)+"/credentials", nil, opts)
}

// RenameCredential renames one of the user's passkeys. 404 when it is revoked or belongs to another user.
func (s *UsersService) RenameCredential(ctx context.Context, externalID, credentialID string, p *CredentialRenameParams, opts ...RequestOption) (*Credential, error) {
	return send[Credential](ctx, s.c, "PATCH", "/v1/users/"+esc(externalID)+"/credentials/"+esc(credentialID), p, true, opts)
}

// Revoke revokes all of the user's passkeys. The user and the audit log stay. Not retried on a 5xx or a
// connection error.
func (s *UsersService) Revoke(ctx context.Context, externalID string, opts ...RequestOption) (*UserRevokeResult, error) {
	return send[UserRevokeResult](ctx, s.c, "POST", "/v1/users/"+esc(externalID)+"/revoke", nil, false, opts)
}

// Delete deletes the user and their passkeys. Cannot be undone; registering the same external_id again makes a
// new user.
func (s *UsersService) Delete(ctx context.Context, externalID string, opts ...RequestOption) (*UserDeleteResult, error) {
	return send[UserDeleteResult](ctx, s.c, "DELETE", "/v1/users/"+esc(externalID), nil, true, opts)
}

// CredentialsService is passkeys by ID (/v1/credentials/:id).
type CredentialsService struct{ c *Client }

// Rename renames a passkey. 404 when it is revoked.
func (s *CredentialsService) Rename(ctx context.Context, credentialID string, p *CredentialRenameParams, opts ...RequestOption) (*Credential, error) {
	return send[Credential](ctx, s.c, "PATCH", "/v1/credentials/"+esc(credentialID), p, true, opts)
}

// Revoke revokes one passkey.
func (s *CredentialsService) Revoke(ctx context.Context, credentialID string, opts ...RequestOption) (*CredentialRevokeResult, error) {
	return send[CredentialRevokeResult](ctx, s.c, "DELETE", "/v1/credentials/"+esc(credentialID), nil, true, opts)
}

// RecoveryService is recovery for a user who lost their device (/v1/recovery/start).
type RecoveryService struct{ c *Client }

// Start issues a recovery token (15 minutes, single use). SealGate does not check who the user is: do that
// yourself first. Not retried on a 5xx or a connection error.
func (s *RecoveryService) Start(ctx context.Context, p *RecoveryStartParams, opts ...RequestOption) (*RecoveryToken, error) {
	return send[RecoveryToken](ctx, s.c, "POST", "/v1/recovery/start", p, false, opts)
}

// AppsService is the API key's app (environment), by its ID app_… (/v1/apps/:id). Another app's ID is 404.
type AppsService struct{ c *Client }

// Get returns the app's settings.
func (s *AppsService) Get(ctx context.Context, appID string, opts ...RequestOption) (*App, error) {
	return get[App](ctx, s.c, "/v1/apps/"+esc(appID), nil, opts)
}

// Update changes ResidentKey and UserVerification (the only settings an API key can change).
func (s *AppsService) Update(ctx context.Context, appID string, p *AppUpdateParams, opts ...RequestOption) (*App, error) {
	return send[App](ctx, s.c, "PATCH", "/v1/apps/"+esc(appID), p, true, opts)
}

// Audit lists audit log entries, newest first (default 200, at most 1000). p may be nil.
func (s *AppsService) Audit(ctx context.Context, appID string, p *AuditListParams, opts ...RequestOption) (*AuditList, error) {
	q := url.Values{}
	if p != nil {
		if p.Event != "" {
			q.Set("event", p.Event)
		}
		if !p.Since.IsZero() {
			q.Set("since", p.Since.UTC().Format(time.RFC3339Nano))
		}
		if p.Limit > 0 {
			q.Set("limit", strconv.Itoa(p.Limit))
		}
	}
	return get[AuditList](ctx, s.c, "/v1/apps/"+esc(appID)+"/audit", q, opts)
}

// Stats returns MAU and registrations for the last 6 months, logins for the last 30 days, users and transports.
func (s *AppsService) Stats(ctx context.Context, appID string, opts ...RequestOption) (*Stats, error) {
	return get[Stats](ctx, s.c, "/v1/apps/"+esc(appID)+"/stats", nil, opts)
}
