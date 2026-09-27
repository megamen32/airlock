package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"
)

func TestOutputLostResponseRetryPersistsOnce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("output_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
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
	_, err = database.Pool().Exec(ctx, `CREATE TABLE agent_messages(id uuid PRIMARY KEY,conversation_id uuid NOT NULL,role text NOT NULL,content text NOT NULL,parts jsonb,run_id uuid,source text NOT NULL,ephemeral boolean NOT NULL,file_keys text[],cost_estimate numeric)`)
	if err != nil {
		t.Fatal(err)
	}
	deps := PostDeps{DB: database}
	opts := PostOpts{AgentID: uuid.New(), ConversationID: uuid.New(), IdempotencyKey: uuid.NewString(), Role: "assistant", Text: "finished", Source: "notification", Ephemeral: true, Parts: []wire.DisplayPart{{Type: "text", Text: "finished"}}}
	raw, _ := json.Marshal(opts.Parts)
	inserted, err := storeIdempotentOutput(ctx, deps, opts, opts.Text, raw, pgtype.UUID{})
	if err != nil || !inserted {
		t.Fatalf("initial=%v %v", inserted, err)
	}
	// Simulate lost HTTP success: caller retries, including concurrent retries.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, e := storeIdempotentOutput(ctx, deps, opts, opts.Text, raw, toPgUUID(uuid.New()))
			if e != nil || got {
				t.Errorf("retry inserted=%v err=%v", got, e)
			}
		}()
	}
	wg.Wait()
	var count int
	if err = database.Pool().QueryRow(ctx, `SELECT count(*) FROM agent_messages`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("count=%d %v", count, err)
	}
	if _, err = storeIdempotentOutput(ctx, deps, opts, "different", raw, pgtype.UUID{}); err == nil {
		t.Fatal("key payload conflict accepted")
	}
	opts.ConversationID = uuid.New()
	if inserted, err = storeIdempotentOutput(ctx, deps, opts, opts.Text, raw, pgtype.UUID{}); err != nil || !inserted {
		t.Fatalf("different conversation incorrectly deduped %v %v", inserted, err)
	}
	_, err = database.Pool().Exec(ctx, `CREATE TABLE agent_conversations(id uuid PRIMARY KEY,agent_id uuid,bridge_id uuid,user_id uuid,source text,external_id text,title text DEFAULT '',metadata jsonb DEFAULT '{}',settings jsonb DEFAULT '{}',context_checkpoint_message_id uuid,created_at timestamptz DEFAULT now(),updated_at timestamptz DEFAULT now(),user_activity_at timestamptz DEFAULT now(),notification_route_lost_at timestamptz)`)
	if err != nil {
		t.Fatal(err)
	}
	opts.ConversationID = uuid.New()
	opts.Parts = nil // Text-only is a supported real call path, not an empty delivery.
	_, err = database.Pool().Exec(ctx, `INSERT INTO agent_conversations(id,agent_id,bridge_id,user_id,source,external_id) VALUES($1,$2,$3,$4,'bridge','42')`, opts.ConversationID, opts.AgentID, uuid.New(), uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	bridge := &receiptBridge{receipts: map[string]string{}}
	deps.BridgeMgr = bridge
	deps.Logger = zap.NewNop()
	if err = PostToConversation(ctx, deps, opts); err == nil {
		t.Fatal("lost bridge response reported success")
	}
	for i := 0; i < 3; i++ {
		if err = PostToConversation(ctx, deps, opts); err != nil {
			t.Fatal(err)
		}
	}
	if bridge.deliveries != 1 || bridge.text != opts.Text {
		t.Fatalf("lost response replay delivery count=%d text=%q", bridge.deliveries, bridge.text)
	}
	if err = database.Pool().QueryRow(ctx, `SELECT count(*) FROM agent_messages WHERE conversation_id=$1`, opts.ConversationID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replayed persistence %d %v", count, err)
	}
	opts.Text = "changed payload"
	if err = PostToConversation(ctx, deps, opts); err == nil || bridge.deliveries != 1 {
		t.Fatal("changed payload reached relay")
	}
}

// Models the durable relay contract: first acceptance loses its HTTP response;
// retries acknowledge the same receipt without performing delivery again.
type receiptBridge struct {
	receipts   map[string]string
	deliveries int
	text       string
}

func (*receiptBridge) SupportsOutputOnce(context.Context, uuid.UUID) bool { return true }
func (*receiptBridge) SendParts(context.Context, uuid.UUID, string, []wire.DisplayPart) error {
	return errors.New("unkeyed delivery used")
}
func (b *receiptBridge) SendPartsOnce(_ context.Context, _ uuid.UUID, _ string, key string, parts []wire.DisplayPart) error {
	if len(parts) != 1 || parts[0].Text == "" {
		return errors.New("missing text delivery")
	}
	if previous, ok := b.receipts[key]; ok {
		if previous != parts[0].Text {
			return errors.New("key payload changed")
		}
		return nil
	}
	b.receipts[key] = parts[0].Text
	b.text = parts[0].Text
	b.deliveries++
	return errors.New("response lost after acceptance")
}
