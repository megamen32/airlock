package trigger

import (
	"bytes"
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

func TestUserbotExportedFileDownloadsStorageWithoutRelayCredential(t *testing.T) {
	data := []byte("native exported report")
	storageCalls, relayCalls := 0, 0
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		storageCalls++
		if r.Header.Get("Authorization") != "" {
			t.Error("relay credential leaked to storage")
		}
		if r.URL.Query().Get("signature") != "presigned-test" {
			t.Error("presigned query lost")
		}
		w.Write(data)
	}))
	defer storage.Close()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayCalls++
		if r.Header.Get("Authorization") != "Bearer test-relay-token" {
			t.Error("missing relay credential")
		}
		var body struct {
			Data     []byte `json:"dataBase64"`
			Filename string `json:"filename"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body.Data, data) || body.Filename != "report.md" {
			t.Error("exported file changed")
		}
		w.Write([]byte(`{"delivered":true}`))
	}))
	defer relay.Close()
	driver := &UserbotDriver{baseURL: relay.URL, client: relay.Client(), storageOrigin: storage.URL}
	err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "file", Filename: "report.md", URL: storage.URL + "/bucket/report?signature=presigned-test"}})
	if err != nil || storageCalls != 1 || relayCalls != 1 {
		t.Fatalf("storage=%d relay=%d err=%v", storageCalls, relayCalls, err)
	}
}

func TestUserbotExportRejectsUnknownOriginBeforeNetwork(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Write([]byte("untrusted")) }))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client(), storageOrigin: "https://configured-storage.invalid"}
	err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "file", URL: server.URL + "/private"}})
	if err == nil || calls != 0 {
		t.Fatalf("untrusted origin reached: calls=%d err=%v", calls, err)
	}
}

func TestUserbotExportStorageFailureNeverCallsRelay(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			relayCalls := 0
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { relayCalls++ }))
			defer relay.Close()
			storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "SECRET signed storage error", status) }))
			defer storage.Close()
			driver := &UserbotDriver{baseURL: relay.URL, client: relay.Client(), storageOrigin: storage.URL}
			err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "file", URL: storage.URL + "/report"}})
			if err == nil || relayCalls != 0 || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("relay=%d err=%v", relayCalls, err)
			}
		})
	}
}

func TestUserbotExportDoesNotFollowRedirect(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++ }))
	defer target.Close()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer storage.Close()
	driver := &UserbotDriver{baseURL: target.URL, client: target.Client(), storageOrigin: storage.URL}
	err := driver.SendParts(context.Background(), relayTestBridge(), "123", []wire.DisplayPart{{Type: "file", URL: storage.URL + "/report"}})
	if err == nil || targetCalls != 0 {
		t.Fatalf("redirect followed: calls=%d err=%v", targetCalls, err)
	}
}

func TestUserbotPollRetrievesDurableFileReference(t *testing.T) {
	ref := strings.Repeat("a", 64)
	data := []byte("durable attachment")
	fileCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-relay-token" {
			t.Error("unauthenticated file reference")
		}
		if r.URL.Path == "/events" {
			json.NewEncoder(w).Encode(map[string]any{"nextCursor": 5, "events": []userbotEvent{{Seq: 5, MessageID: "20", ChatID: "123", SenderID: "123", Direct: true, Files: []userbotFile{{Filename: "photo.jpg", FileRef: ref}}}}})
			return
		}
		if r.URL.Path != "/files/"+ref {
			t.Errorf("wrong file URL: %s", r.URL.Path)
		}
		fileCalls++
		w.Write(data)
	}))
	defer server.Close()
	driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
	br := relayTestBridge()
	events, err := driver.Poll(context.Background(), &br)
	if err != nil || len(events) != 1 || fileCalls != 1 {
		t.Fatalf("events=%d fileCalls=%d err=%v", len(events), fileCalls, err)
	}
	if !bytes.Equal(events[0].Files[0].Data, data) || events[0].Files[0].Size != int64(len(data)) {
		t.Fatal("reference bytes not hydrated")
	}
}

func TestUserbotFileReferenceFailureKeepsCursor(t *testing.T) {
	for _, ref := range []string{strings.Repeat("b", 64), "../../secret", strings.Repeat("z", 64)} {
		t.Run(ref[:8], func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/events" {
					json.NewEncoder(w).Encode(map[string]any{"nextCursor": 5, "events": []userbotEvent{{Seq: 5, MessageID: "20", ChatID: "123", SenderID: "123", Direct: true, Files: []userbotFile{{Filename: "photo.jpg", FileRef: ref}}}}})
					return
				}
				calls++
				http.Error(w, "missing", http.StatusNotFound)
			}))
			defer server.Close()
			driver := &UserbotDriver{baseURL: server.URL, client: server.Client()}
			br := relayTestBridge()
			before := string(br.Config)
			events, err := driver.Poll(context.Background(), &br)
			if err == nil || len(events) != 0 || string(br.Config) != before {
				t.Fatal("failed attachment advanced cursor")
			}
			if ref != strings.Repeat("b", 64) && calls != 0 {
				t.Fatal("invalid reference triggered file request")
			}
		})
	}
}

func TestUserbotDeliveryKeyDoesNotChangeWhenRetriedModelTextChanges(t *testing.T) {
	ctx := context.WithValue(context.Background(), relayIncomingKey{}, "bridge:123:20")
	if relayDeliveryKey(ctx, "123:0", "original") != relayDeliveryKey(ctx, "123:0", "regenerated") {
		t.Fatal("changed model output bypasses same-delivery receipt")
	}
	if relayDeliveryKey(ctx, "123:0", "same") == relayDeliveryKey(ctx, "123:1", "same") {
		t.Fatal("separate delivery parts collide")
	}
}

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
