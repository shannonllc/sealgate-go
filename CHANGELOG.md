# Changelog

## 0.2.0 (2026-11-13)

- `Users.Update`: change the display name SealGate stores for a user (`PATCH /v1/users/:external_id`). Registering more passkeys does not change it.
- The `user.updated` webhook event and audit log event.

## 0.1.0 (2026-10-17)

- First release: passkey registration and login (`Register.Options` / `Register.Verify`, `Login.Options` / `Login.Verify`), users and passkeys (`Users`, `Credentials`), recovery tokens (`Recovery.Start`), the app settings, audit log and stats (`Apps`), and webhook verification (`VerifyWebhook`, `Webhook`).
