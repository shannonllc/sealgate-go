# sealgate-go

Go SDK for [SealGate](https://sealgate.jp/), the passkey authentication API that adds passkey login to your existing login.

- Standard library only.
- Go 1.21+. Every call takes a `context.Context`.
- Server-side only. In the browser, use [sealgate-browser](https://www.npmjs.com/package/sealgate-browser): it runs the passkey dialog and posts to your server, and your server relays to SealGate with this SDK.

## Install

```sh
go get github.com/shannonllc/sealgate-go
```

```go
import sealgate "github.com/shannonllc/sealgate-go"
```

## Quick start

```go
sg, err := sealgate.NewClient("sk_live_...") // or set SEALGATE_API_KEY
if err != nil {
	log.Fatal(err)
}

// Login, step 1: return start to the browser SDK as is
start, err := sg.Login.Options(ctx, nil) // or &sealgate.LoginOptionsParams{ExternalID: "user-123"}

// Login, step 2: verify what the browser SDK sent back, then start your own session
r, err := sg.Login.Verify(ctx, &sealgate.LoginVerifyParams{ChallengeID: body.ChallengeID, Response: body.Response})
createSession(r.ExternalID)
```

`Response` is a `json.RawMessage`: pass the browser's JSON through unchanged. API keys belong to an environment: Live keys start with `sk_live_` and Test keys with `sk_test_` (Test environment users are not billed). Use the API key on your server only.

## Registration

```go
// On a page where the user is logged in. Adding a second passkey needs SignedIn:
// decide it from your session, never from a value the browser sent.
start, err := sg.Register.Options(ctx, &sealgate.RegisterOptionsParams{
	ExternalID:  user.ID,
	DisplayName: user.Email,
	SignedIn:    sealgate.Bool(true),
})

done, err := sg.Register.Verify(ctx, &sealgate.RegisterVerifyParams{ChallengeID: id, Response: resp, Name: "iPhone"})
```

## Users, passkeys and recovery

```go
list, err := sg.Users.ListCredentials(ctx, "user-123") // revoked ones have RevokedAt
_, err = sg.Credentials.Revoke(ctx, "crd_...")
_, err = sg.Users.Revoke(ctx, "user-123") // every passkey of the user
_, err = sg.Users.Delete(ctx, "user-123")  // cannot be undone

// A user who lost their device: check who they are yourself, then
tok, err := sg.Recovery.Start(ctx, &sealgate.RecoveryStartParams{ExternalID: "user-123", Reason: "checked at the counter"})
start, err := sg.Register.Options(ctx, &sealgate.RegisterOptionsParams{ExternalID: "user-123", DisplayName: "taro", RecoveryToken: tok.RecoveryToken})
```

## Webhooks

When you set a webhook URL in the dashboard's environment settings, SealGate POSTs events signed in the [Standard Webhooks](https://www.standardwebhooks.com/) format. The signing secret (`whsec_...`) is under the environment settings' delivery log and signing key. Pass the raw request body.

```go
body, _ := io.ReadAll(r.Body)
ev, err := sealgate.VerifyWebhook(body, r.Header, os.Getenv("SEALGATE_WEBHOOK_SECRET"))
if err != nil {
	w.WriteHeader(http.StatusBadRequest)
	return
}
d, _ := ev.ParseData()
switch ev.Type {
case sealgate.EventLoginSucceeded:
	log.Println(d.ExternalID, d.CredentialID)
case sealgate.EventUserDeleted:
	log.Println(d.EndUserID, d.CredentialsDeleted)
}
```

The error matches `sealgate.ErrWebhookVerification` when the signature does not match or the timestamp is more than 5 minutes off (`sealgate.WithTolerance`). Pass `sealgate.WithSecrets(old)` while you switch to a new secret. A redelivery has the same `webhook-id` header. Events: `register.completed`, `register.failed`, `login.succeeded`, `login.failed`, `credential.revoked`, `credential.renamed`, `user.revoked`, `user.deleted` and `recovery.issued` (see `EventData`).

## API

| Method | Endpoint |
|---|---|
| `Register.Options` | `POST /v1/register/options` |
| `Register.Verify` | `POST /v1/register/verify` |
| `Login.Options` | `POST /v1/login/options` |
| `Login.Verify` | `POST /v1/login/verify` |
| `Users.ListCredentials` | `GET /v1/users/:external_id/credentials` |
| `Users.RenameCredential` | `PATCH /v1/users/:external_id/credentials/:id` |
| `Users.Revoke` | `POST /v1/users/:external_id/revoke` |
| `Users.Delete` | `DELETE /v1/users/:external_id` |
| `Credentials.Rename` | `PATCH /v1/credentials/:id` |
| `Credentials.Revoke` | `DELETE /v1/credentials/:id` |
| `Recovery.Start` | `POST /v1/recovery/start` |
| `Apps.Get` | `GET /v1/apps/:id` |
| `Apps.Update` | `PATCH /v1/apps/:id` |
| `Apps.Audit` | `GET /v1/apps/:id/audit` |
| `Apps.Stats` | `GET /v1/apps/:id/stats` |

Every method takes `sealgate.WithRequestTimeout` and `sealgate.WithRequestMaxRetries`. The app ID (`app_...`) must be the API key's own app. The audit log is one list, newest first (up to 1000 entries); there are no further pages, so narrow it with `Since` and `Limit`.

## Errors

Every error is a `*sealgate.Error` with `Kind`, `Status`, `Code` (the API error code) and `Message`. Match the kind with `errors.Is`:

| Sentinel | When |
|---|---|
| `ErrValidation` | 400 `invalid_request` |
| `ErrAuthentication` | 401 `invalid_api_key` |
| `ErrVerification` | 401 `verification_failed`: the passkey response did not verify |
| `ErrPaymentRequired` | 402 `mau_limit` |
| `ErrPermission` | 403 `credential_revoked`, `origin_not_allowed`, `recovery_not_allowed` |
| `ErrNotFound` | 404 `not_found` |
| `ErrChallengeExpired` | 410 `challenge_expired`: start again from Options |
| `ErrRateLimit` | 429 `rate_limited`, after retries. `RetryAfter` |
| `ErrAPI` | other responses, including 5xx |
| `ErrConnection` / `ErrTimeout` | no response, or the timeout reached |
| `ErrWebhookVerification` | `VerifyWebhook` failed |
| `ErrInvalidArgument` | a missing API key, an invalid webhook secret |

## Retries and timeouts

`sealgate.WithTimeout(30 * time.Second)` and `sealgate.WithMaxRetries(2)` are the defaults. 429 is retried for every request, waiting `retry-after` (up to one minute). 5xx, timeouts and connection errors are retried only for requests safe to repeat (GET, PATCH, DELETE), with exponential backoff from 0.5 s. POST requests (starting and finishing registration and login, revoking a user, issuing a recovery token) are not retried on those: a challenge can be used only once.

## Links

- API reference: https://sealgate.jp/docs
- Changelog: [CHANGELOG.md](./CHANGELOG.md)
- License: MIT
