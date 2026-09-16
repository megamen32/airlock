package runtime

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
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
}
