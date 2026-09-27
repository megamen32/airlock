package trigger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func relayTestBridge() dbq.Bridge {
	return dbq.Bridge{ID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, Type: "telegram_userbot", BotTokenRef: "test-relay-token", Config: []byte(`{"after":4}`)}
}

func TestUserbotPollPreservesIdentityFilesAndExactConfirmation(t *testing.T) {
	runID := uuid.NewString()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-relay-token" {
			t.Error("missing relay authentication")
		}
		if r.URL.RawQuery != "after=4" {
			t.Errorf("wrong cursor %s", r.URL.RawQuery)
		}
		json.NewEncoder(w).Encode(map[string]any{"nextCursor": 6, "events": []userbotEvent{
			{Seq: 5, MessageID: "20", ChatID: "123", SenderID: "123", Direct: true, Text: "hello", Files: []userbotFile{{Filename: "report.txt", ContentType: "text/plain", Data: []byte("actual bytes")}}},
			{Seq: 6, MessageID: "21", ChatID: "-456", SenderID: "123", Text: "/approve " + runID},
		}})
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	br := relayTestBridge()
	events, err := driver.Poll(context.Background(), &br)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ExternalID != "123" || events[1].SenderID != "123" {
		t.Fatalf("wrong attribution: %+v", events)
	}
	if string(events[0].Files[0].Data) != "actual bytes" || events[0].Files[0].Size != 12 {
		t.Fatal("file data or size lost")
	}
	if events[1].Callback == nil || events[1].Callback.Data != "approve:"+runID || events[1].Text != "" {
		t.Fatal("confirmation must reference exact native run")
	}
	if string(br.Config) != `{"after":6}` {
		t.Fatalf("cursor: %s", br.Config)
	}
}

func TestUserbotPollRejectsInvalidBatchWithoutAdvancingCursor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		events []userbotEvent
		cursor int64
	}{
		{"duplicate", []userbotEvent{{Seq: 5, MessageID: "1", ChatID: "123", SenderID: "123", Direct: true}, {Seq: 5, MessageID: "2", ChatID: "123", SenderID: "123", Direct: true}}, 5},
		{"identity mismatch", []userbotEvent{{Seq: 5, MessageID: "1", ChatID: "123", SenderID: "999", Direct: true}}, 5},
		{"cursor skips", []userbotEvent{{Seq: 5, MessageID: "1", ChatID: "123", SenderID: "123", Direct: true}}, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"events": tc.events, "nextCursor": tc.cursor})
			}))
			defer server.Close()
			driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
			br := relayTestBridge()
			before := string(br.Config)
			events, err := driver.Poll(context.Background(), &br)
			if err == nil || len(events) != 0 || string(br.Config) != before {
				t.Fatalf("invalid batch advanced: %s error %v", br.Config, err)
			}
		})
	}
}

func TestUserbotSendDoesNotRetryAmbiguousRelayResponse(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "private internal data", http.StatusConflict)
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "text", Text: "native reply"}})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "private internal") {
		t.Fatal("relay response body leaked")
	}
}

func TestUserbotRetryUsesSameKeyForSameInboundAndPayload(t *testing.T) {
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		keys = append(keys, body["idempotencyKey"].(string))
		w.Write([]byte(`{"delivered":true}`))
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	ctx := context.WithValue(context.Background(), relayIncomingKey{}, "bridge:123:20")
	for i := 0; i < 2; i++ {
		if err := driver.SendParts(ctx, relayTestBridge(), "123", []wire.DisplayPart{{Type: "text", Text: "native reply"}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Fatal("same input lost durable idempotency")
	}
}

func TestUserbotSendStreamPreservesConfirmationAndHidesProviderError(t *testing.T) {
	var texts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		texts = append(texts, body["text"])
		w.Write([]byte(`{"delivered":true}`))
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	runID := uuid.NewString()
	events := make(chan ResponseEvent, 3)
	events <- ResponseEvent{Type: "text-delta", Text: "Answer"}
	events <- ResponseEvent{Type: "confirmation_required", Description: "Send approved report", RunID: runID}
	events <- ResponseEvent{Type: "error", Text: "SECRET provider details"}
	close(events)
	_, err := driver.SendStream(context.Background(), relayTestBridge(), "123", false, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(texts) != 3 || !strings.Contains(texts[1], "/approve "+runID) || strings.Contains(strings.Join(texts, ""), "SECRET") {
		t.Fatalf("bad stream delivery %v", texts)
	}
}

func TestUserbotFileDeliveryEncodesRawBytes(t *testing.T) {
	data := []byte{0, 1, 2, 255}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Data     []byte `json:"dataBase64"`
			Filename string `json:"filename"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/file" || body.Filename != "proof.bin" || !reflect.DeepEqual(body.Data, data) {
			t.Error("file payload changed")
		}
		w.Write([]byte(`{"delivered":true}`))
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	if err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "file", Filename: "proof.bin", Data: data}}); err != nil {
		t.Fatal(err)
	}
}
