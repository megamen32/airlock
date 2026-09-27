package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"
)

func TestUserbotDurableInbox(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("inbox_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Terminate(context.Background())
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database := db.New(ctx, dsn)
	defer database.Close()
	_, err = database.Pool().Exec(ctx, `CREATE TABLE bridges(id uuid PRIMARY KEY,config jsonb,last_polled_at timestamptz,status text,updated_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../db/migrations/013_userbot_inbox.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Pool().Exec(ctx, strings.Split(string(migration), "-- +goose Down")[0])
	if err != nil {
		t.Fatal(err)
	}
	m := &BridgeManager{db: database, logger: zap.NewNop()}
	br := dbq.Bridge{ID: toPgUUID(uuid.New()), Type: "telegram_userbot", Config: []byte(`{"after":3}`)}
	_, err = database.Pool().Exec(ctx, `INSERT INTO bridges(id,config,status) VALUES($1,'{"after":0}','active')`, br.ID)
	if err != nil {
		t.Fatal(err)
	}
	event := func(seq int64, text string) BridgeEvent {
		raw, _ := json.Marshal(userbotEvent{Seq: seq, MessageID: strconv.FormatInt(seq, 10), ChatID: "42", SenderID: "42", Text: text, Direct: true})
		return BridgeEvent{BridgeID: pgUUID(br.ID), ExternalID: "42", SenderID: "42", Text: text, RawPayload: raw}
	}
	events := []BridgeEvent{event(1, "first"), event(2, "second"), event(3, "cancel")}
	events[2].Callback = &BridgeCallback{Data: "cancel:" + uuid.NewString()}
	if err = m.stageUserbotEvents(ctx, br, events); err != nil {
		t.Fatal(err)
	}
	seq, _, err := m.claimUserbotEvent(ctx, br, false)
	if err != nil || seq != 1 {
		t.Fatalf("first claim %d %v", seq, err)
	}
	// A running normal request must not hold up a cancellation receipt.
	cancelSeq, _, err := m.claimUserbotEvent(ctx, br, true)
	if err != nil || cancelSeq != 3 {
		t.Fatalf("cancel bypass %d %v", cancelSeq, err)
	}
	if err = m.finishUserbotEvent(ctx, br, cancelSeq, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.finishUserbotEvent(ctx, br, seq, nil); err != nil {
		t.Fatal(err)
	}
	seq, _, err = m.claimUserbotEvent(ctx, br, false)
	if err != nil || seq != 2 {
		t.Fatalf("second claim %d %v", seq, err)
	}
	if err = m.finishUserbotEvent(ctx, br, seq, errors.New("ambiguous delivery")); err != nil {
		t.Fatal(err)
	}
	// Lost cursor acknowledgement / replay cannot rerun either successful or failed operations.
	if err = m.stageUserbotEvents(ctx, br, events); err != nil {
		t.Fatal(err)
	}
	if _, _, err = m.claimUserbotEvent(ctx, br, false); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("replayed work: %v", err)
	}
	var completed, failed int
	if err = database.Pool().QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='completed'),count(*) FILTER (WHERE status='failed') FROM userbot_inbox`).Scan(&completed, &failed); err != nil || completed != 2 || failed != 1 {
		t.Fatalf("receipts %d %d %v", completed, failed, err)
	}
	// A poisoned later identity rolls back BOTH earlier staging and cursor.
	br.Config = []byte(`{"after":5}`)
	if err = m.stageUserbotEvents(ctx, br, []BridgeEvent{event(4, "new"), event(2, "changed")}); err == nil {
		t.Fatal("payload collision accepted")
	}
	var after, count int
	if err = database.Pool().QueryRow(ctx, `SELECT (config->>'after')::int FROM bridges WHERE id=$1`, br.ID).Scan(&after); err != nil || after != 3 {
		t.Fatalf("cursor advanced across rollback: %d %v", after, err)
	}
	if err = database.Pool().QueryRow(ctx, `SELECT count(*) FROM userbot_inbox WHERE seq=4`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial staging survived: %d %v", count, err)
	}
	// Recovery marks a previously started operation interrupted, without executing it.
	br.Config = []byte(`{"after":4}`)
	if err = m.stageUserbotEvents(ctx, br, []BridgeEvent{event(4, "interrupted")}); err != nil {
		t.Fatal(err)
	}
	if seq, _, err = m.claimUserbotEvent(ctx, br, false); err != nil || seq != 4 {
		t.Fatal(seq, err)
	}
	recoveryCtx, stop := context.WithTimeout(ctx, 400*time.Millisecond)
	m.runUserbotInbox(recoveryCtx, br)
	stop()
	var status string
	if err = database.Pool().QueryRow(ctx, `SELECT status FROM userbot_inbox WHERE seq=4`).Scan(&status); err != nil || status != "interrupted" {
		t.Fatalf("recovery %s %v", status, err)
	}
	if _, _, err = m.claimUserbotEvent(ctx, br, false); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("interrupted replay %v", err)
	}
	// Exercise actual BridgeManager->driver->HTTP relay retry keys after a lost
	// acceptance response, independent of runtime's persistence-only regression.
	_, err = database.Pool().Exec(ctx, `ALTER TABLE bridges ADD COLUMN agent_id uuid, ADD COLUMN owner_principal_id uuid,ADD COLUMN type text NOT NULL DEFAULT 'telegram_userbot',ADD COLUMN name text NOT NULL DEFAULT '',ADD COLUMN bot_username text NOT NULL DEFAULT '',ADD COLUMN is_system boolean NOT NULL DEFAULT false,ADD COLUMN settings jsonb DEFAULT '{}',ADD COLUMN bot_token_ref text NOT NULL DEFAULT 'test',ADD COLUMN created_at timestamptz DEFAULT now(),ADD COLUMN managed boolean DEFAULT false,ADD COLUMN telegram_bot_user_id bigint,ADD COLUMN is_manager boolean DEFAULT false,ADD COLUMN manager_error text`)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	if _, err = database.Pool().Exec(ctx, `UPDATE bridges SET manager_error=''`); err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		key := body["idempotencyKey"]
		if key == "" || body["text"] != "scheduled result" || r.Header.Get("Authorization") != "Bearer test" {
			t.Error("invalid keyed output")
		}
		if !keys[key] {
			keys[key] = true
			deliveries++
			http.Error(w, "response lost", 503)
			return
		}
		w.Write([]byte(`{"delivered":true}`))
	}))
	defer server.Close()
	m.drivers = map[string]BridgeDriver{"telegram_userbot": &UserbotDriver{baseURL: server.URL, client: server.Client()}}
	m.encryptor = inboxTestSecrets{}
	if !m.SupportsOutputOnce(ctx, pgUUID(br.ID)) {
		t.Fatal("keyed output unsupported")
	}
	parts := []wire.DisplayPart{{Type: "text", Text: "scheduled result"}}
	if err = m.SendPartsOnce(ctx, pgUUID(br.ID), "42", "job:1", parts); err == nil {
		t.Fatal("ambiguous send returned success")
	}
	if err = m.SendPartsOnce(ctx, pgUUID(br.ID), "42", "job:1", parts); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || len(keys) != 1 {
		t.Fatalf("ambiguous retry duplicated HTTP relay delivery: %d", deliveries)
	}
	// A completion-write outage must stop BOTH lanes, recover the ambiguous
	// first event as interrupted, and resume the next event without restart.
	br.Config = []byte(`{"after":6}`)
	if err = m.stageUserbotEvents(ctx, br, []BridgeEvent{event(5, "first ambiguous"), event(6, "later request")}); err != nil {
		t.Fatal(err)
	}
	_, err = database.Pool().Exec(ctx, `CREATE FUNCTION reject_first_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.seq=5 AND NEW.status='completed' THEN RAISE EXCEPTION 'simulated completion write outage'; END IF; RETURN NEW; END $$;
CREATE TRIGGER reject_first_receipt BEFORE UPDATE ON userbot_inbox FOR EACH ROW EXECUTE FUNCTION reject_first_receipt()`)
	if err != nil {
		t.Fatal(err)
	}
	var firstCalls, secondCalls atomic.Int32
	workerCtx, stopWorker := context.WithTimeout(ctx, 5*time.Second)
	defer stopWorker()
	done := make(chan struct{})
	go func() {
		defer close(done)
		m.superviseUserbotInbox(workerCtx, br, func(_ context.Context, ev BridgeEvent) error {
			if ev.Text == "first ambiguous" {
				firstCalls.Add(1)
			} else if ev.Text == "later request" {
				secondCalls.Add(1)
			} else {
				t.Errorf("unexpected event %q", ev.Text)
			}
			return nil
		})
	}()
	for workerCtx.Err() == nil {
		if err = database.Pool().QueryRow(ctx, `SELECT status FROM userbot_inbox WHERE seq=6`).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stopWorker()
	<-done
	if status != "completed" || firstCalls.Load() != 1 || secondCalls.Load() != 1 {
		t.Fatalf("worker did not recover: status=%s first=%d second=%d", status, firstCalls.Load(), secondCalls.Load())
	}
	if err = database.Pool().QueryRow(ctx, `SELECT status FROM userbot_inbox WHERE seq=5`).Scan(&status); err != nil || status != "interrupted" {
		t.Fatalf("ambiguous first event replayed: %s %v", status, err)
	}
}

type inboxTestSecrets struct{ secrets.Store }

func (inboxTestSecrets) Get(_ context.Context, _, stored string) (string, error) { return stored, nil }
