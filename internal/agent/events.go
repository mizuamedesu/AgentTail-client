package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

func (k *Key) events(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		k.eventConnection(ctx)
		k.RequestSync() // every reconnect revalidates the complete configuration
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 10*time.Second)
	}
}
func (k *Key) eventConnection(ctx context.Context) {
	client := *k.options.Client.HTTP
	client.Timeout = 0
	dial, cancel := context.WithTimeout(ctx, RequestTimeout)
	connection, _, err := websocket.Dial(dial, k.options.Client.Origin+"/api/agent/events?instance_id="+k.instance, &websocket.DialOptions{HTTPClient: &client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + k.options.Client.Token}}})
	cancel()
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(8192)
	// The DO checks this instance's current D1 lease before each notification,
	// so the socket can stay hibernated across many lease renewals.
	socketContext, cancel := context.WithCancel(ctx)
	defer cancel()
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		timer := time.NewTicker(20 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-socketContext.Done():
				return
			case <-timer.C:
				write, cancel := context.WithTimeout(socketContext, RequestTimeout)
				err := connection.Write(write, websocket.MessageText, []byte("ping"))
				cancel()
				if err != nil {
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-pingDone }()
	k.RequestSync()
	for {
		typeID, payload, err := connection.Read(socketContext)
		if err != nil {
			if websocket.CloseStatus(err) == 4003 {
				k.hardStop("KILLED", false)
			}
			return
		}
		if typeID != websocket.MessageText {
			return
		}
		if string(payload) == "pong" {
			continue
		}
		var event struct {
			Type  string  `json:"type"`
			KeyID *string `json:"key_id"`
		}
		if json.Unmarshal(payload, &event) != nil {
			return
		}
		switch event.Type {
		case "key.revoked", "device.revoked":
			if event.KeyID != nil && *event.KeyID == k.id {
				k.hardStop("UNAUTHENTICATED", true)
			}
		case "account.reset", "account.disabled":
			k.hardStop("UNAUTHENTICATED", true)
		case "kill.enabled":
			k.hardStop("KILLED", false)
		case "relay.stopped":
			k.relayAllowed.Store(false)
			k.stopRelay()
		case "acl.changed":
			k.stopRelay() // the provider revokes these credentials too
		}
		k.RequestSync()
	}
}
