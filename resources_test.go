package sealgate

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func check(t *testing.T, f *fakeAPI, method, path, query, body string) {
	t.Helper()
	c := f.Last()
	if c.Method != method || c.Path != path || c.Query != query || string(c.Raw) != body {
		t.Fatalf("got %s %s ?%s %s, want %s %s ?%s %s", c.Method, c.Path, c.Query, c.Raw, method, path, query, body)
	}
}

func TestResources(t *testing.T) {
	ctx := context.Background()
	raw := json.RawMessage(`{"id":"x"}`)

	t.Run("register", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"challenge_id": "chl_1", "end_user_id": "eu_1", "options": map[string]any{"challenge": "c"}}))
		c, _ := testClient(t, f)
		r, err := c.Register.Options(ctx, &RegisterOptionsParams{ExternalID: "u1", DisplayName: "taro", SignedIn: Bool(true)})
		if err != nil || r.ChallengeID != "chl_1" || r.EndUserID != "eu_1" {
			t.Fatal(r, err)
		}
		check(t, f, "POST", "/v1/register/options", "", `{"external_id":"u1","display_name":"taro","signed_in":true}`)
		_, _ = c.Register.Options(ctx, &RegisterOptionsParams{ExternalID: "u1", DisplayName: "taro", RecoveryToken: "rt_1"})
		check(t, f, "POST", "/v1/register/options", "", `{"external_id":"u1","display_name":"taro","recovery_token":"rt_1"}`)
		_, _ = c.Register.Verify(ctx, &RegisterVerifyParams{ChallengeID: "chl_1", Response: raw, Name: "iPhone"})
		check(t, f, "POST", "/v1/register/verify", "", `{"challenge_id":"chl_1","response":{"id":"x"},"name":"iPhone"}`)
	})

	t.Run("login", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"end_user_id": "eu_1", "external_id": "u1", "credential_id": "crd_1", "user_verified": true, "password_allowed": true}))
		c, _ := testClient(t, f)
		_, _ = c.Login.Options(ctx, nil)
		check(t, f, "POST", "/v1/login/options", "", `{}`)
		_, _ = c.Login.Options(ctx, &LoginOptionsParams{})
		check(t, f, "POST", "/v1/login/options", "", `{}`)
		_, _ = c.Login.Options(ctx, &LoginOptionsParams{ExternalID: "u1"})
		check(t, f, "POST", "/v1/login/options", "", `{"external_id":"u1"}`)
		r, err := c.Login.Verify(ctx, &LoginVerifyParams{ChallengeID: "c", Response: raw})
		if err != nil || r.ExternalID != "u1" || !r.UserVerified || !r.PasswordAllowed {
			t.Fatal(r, err)
		}
		check(t, f, "POST", "/v1/login/verify", "", `{"challenge_id":"c","response":{"id":"x"}}`)
	})

	t.Run("users", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"end_user_id": "eu_1", "data": []any{map[string]any{"id": "crd_1", "name": nil, "transports": []string{"internal"}}}, "revoked": 2, "deleted": true, "credentials_deleted": 2}))
		c, _ := testClient(t, f)
		l, err := c.Users.ListCredentials(ctx, "user/1 太郎")
		if err != nil || len(l.Data) != 1 || l.Data[0].Name != nil || l.Data[0].Transports[0] != "internal" {
			t.Fatal(l, err)
		}
		check(t, f, "GET", "/v1/users/user%2F1%20%E5%A4%AA%E9%83%8E/credentials", "", "")
		_, _ = c.Users.RenameCredential(ctx, "u1", "crd_1", &CredentialRenameParams{Name: "Mac"})
		check(t, f, "PATCH", "/v1/users/u1/credentials/crd_1", "", `{"name":"Mac"}`)
		rv, _ := c.Users.Revoke(ctx, "u1")
		if rv.Revoked != 2 {
			t.Fatal(rv)
		}
		check(t, f, "POST", "/v1/users/u1/revoke", "", "")
		d, _ := c.Users.Delete(ctx, "u1")
		if !d.Deleted || d.CredentialsDeleted != 2 {
			t.Fatal(d)
		}
		check(t, f, "DELETE", "/v1/users/u1", "", "")
	})

	t.Run("credentials and recovery", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"credential_id": "crd_1", "revoked_at": "2026-10-17T00:00:00.000Z", "recovery_token": "rt_1"}))
		c, _ := testClient(t, f)
		_, _ = c.Credentials.Rename(ctx, "crd_1", &CredentialRenameParams{Name: "Pixel"})
		check(t, f, "PATCH", "/v1/credentials/crd_1", "", `{"name":"Pixel"}`)
		r, _ := c.Credentials.Revoke(ctx, "crd_1")
		if *r.RevokedAt != "2026-10-17T00:00:00.000Z" {
			t.Fatal(r)
		}
		check(t, f, "DELETE", "/v1/credentials/crd_1", "", "")
		tok, _ := c.Recovery.Start(ctx, &RecoveryStartParams{ExternalID: "u1", Reason: "checked"})
		if tok.RecoveryToken != "rt_1" {
			t.Fatal(tok)
		}
		check(t, f, "POST", "/v1/recovery/start", "", `{"external_id":"u1","reason":"checked"}`)
		_, _ = c.Recovery.Start(ctx, &RecoveryStartParams{ExternalID: "u1"})
		check(t, f, "POST", "/v1/recovery/start", "", `{"external_id":"u1"}`)
	})

	t.Run("apps", func(t *testing.T) {
		f := newFakeAPI(t, jsonReply(200, map[string]any{"id": "app_1", "resident_key": "required", "users": map[string]any{"total": 3, "with_passkey": 2}, "data": []any{}}))
		c, _ := testClient(t, f)
		a, _ := c.Apps.Get(ctx, "app_1")
		if a.ResidentKey != "required" {
			t.Fatal(a)
		}
		check(t, f, "GET", "/v1/apps/app_1", "", "")
		_, _ = c.Apps.Update(ctx, "app_1", &AppUpdateParams{UserVerification: "required"})
		check(t, f, "PATCH", "/v1/apps/app_1", "", `{"user_verification":"required"}`)
		_, _ = c.Apps.Audit(ctx, "app_1", nil)
		check(t, f, "GET", "/v1/apps/app_1/audit", "", "")
		_, _ = c.Apps.Audit(ctx, "app_1", &AuditListParams{})
		check(t, f, "GET", "/v1/apps/app_1/audit", "", "")
		jst := time.FixedZone("JST", 9*3600)
		_, _ = c.Apps.Audit(ctx, "app_1", &AuditListParams{Event: "login.failed", Since: time.Date(2026, 10, 1, 9, 0, 0, 0, jst), Limit: 50})
		check(t, f, "GET", "/v1/apps/app_1/audit", "event=login.failed&limit=50&since=2026-10-01T00%3A00%3A00Z", "")
		s, _ := c.Apps.Stats(ctx, "app_1")
		if s.Users.WithPasskey != 2 {
			t.Fatal(s)
		}
		check(t, f, "GET", "/v1/apps/app_1/stats", "", "")
	})
}
