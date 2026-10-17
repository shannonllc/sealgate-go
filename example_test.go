package sealgate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	sealgate "github.com/shannonllc/sealgate-go"
)

// Relays the browser SDK to SealGate: login, step 1 and step 2.
func Example() {
	sg, err := sealgate.NewClient(os.Getenv("SEALGATE_API_KEY"))
	if err != nil {
		return
	}
	ctx := context.Background()

	// Step 1: return start to the browser SDK as is
	start, err := sg.Login.Options(ctx, nil)
	if err != nil {
		return
	}
	_ = start

	// Step 2: the browser SDK posts { challenge_id, response }
	var body struct {
		ChallengeID string          `json:"challenge_id"`
		Response    json.RawMessage `json:"response"`
	}
	r, err := sg.Login.Verify(ctx, &sealgate.LoginVerifyParams{ChallengeID: body.ChallengeID, Response: body.Response})
	if errors.Is(err, sealgate.ErrChallengeExpired) {
		return // start again
	}
	if err != nil {
		return
	}
	fmt.Println(r.ExternalID) // start your own session for this user
}

// Receives a webhook. Pass the raw body.
func ExampleVerifyWebhook() {
	http.HandleFunc("/webhooks/sealgate", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ev, err := sealgate.VerifyWebhook(body, r.Header, os.Getenv("SEALGATE_WEBHOOK_SECRET"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if ev.Type == sealgate.EventLoginSucceeded {
			d, _ := ev.ParseData()
			fmt.Println(d.ExternalID)
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
