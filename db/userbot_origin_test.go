package db

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// Applies the shipped migration SQL, not a copy of its replacement predicate.
// Minimal predecessor tables isolate CHECK semantics from unrelated platform
// migrations; the production admission service separately validates identity.
func TestUserbotOriginMigrationPreservesIdentityBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("origin_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Terminate(context.Background())
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database := New(ctx, dsn)
	defer database.Close()
	_, err = database.Pool().Exec(ctx, `CREATE TABLE bridges(id uuid PRIMARY KEY,type text NOT NULL,status text NOT NULL,settings jsonb);
CREATE TABLE execution_origins(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),credential_profile text NOT NULL,ingress text NOT NULL,bridge_id uuid,platform_identity_id uuid,sender_id text,chat_id text,
CONSTRAINT execution_origins_check5 CHECK (credential_profile <> 'bridge' OR (ingress='bridge' AND bridge_id IS NOT NULL AND platform_identity_id IS NOT NULL AND sender_id IS NOT NULL AND chat_id IS NOT NULL AND chat_id=sender_id)))`)
	if err != nil {
		t.Fatal(err)
	}
	allowed, bot, inactive, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, b := range []struct {
		id                     uuid.UUID
		kind, status, settings string
	}{
		{allowed, "telegram_userbot", "active", `{"allowed_chat_ids":["-456","not-group"]}`},
		{bot, "telegram", "active", `{"allowed_chat_ids":["-456"]}`},
		{inactive, "telegram_userbot", "disabled", `{"allowed_chat_ids":["-456"]}`},
		{other, "telegram_userbot", "active", `{"allowed_chat_ids":["-789"]}`},
	} {
		if _, err = database.Pool().Exec(ctx, `INSERT INTO bridges VALUES($1,$2,$3,$4)`, b.id, b.kind, b.status, b.settings); err != nil {
			t.Fatal(err)
		}
	}
	insert := func(bridge any, sender, chat any, identity any) error {
		_, e := database.Pool().Exec(ctx, `INSERT INTO execution_origins(credential_profile,ingress,bridge_id,platform_identity_id,sender_id,chat_id) VALUES('bridge','bridge',$1,$2,$3,$4)`, bridge, identity, sender, chat)
		return e
	}
	identity := uuid.New()
	if err = insert(allowed, "123", "123", identity); err != nil {
		t.Fatal("preexisting DM", err)
	}
	if err = insert(allowed, "123", "-456", identity); err == nil {
		t.Fatal("pre-migration group unexpectedly allowed")
	}
	raw, err := os.ReadFile("migrations/015_userbot_group_origins.sql")
	if err != nil {
		t.Fatal(err)
	}
	sections := strings.Split(string(raw), "-- +goose Down")
	if len(sections) != 2 {
		t.Fatal("missing down migration")
	}
	if _, err = database.Pool().Exec(ctx, sections[0]); err != nil {
		t.Fatal("apply actual up migration", err)
	}
	for _, tc := range []struct {
		name                           string
		bridge, sender, chat, identity any
		allowed                        bool
	}{
		{"userbot DM", allowed, "123", "123", identity, true},
		{"Bot API DM", bot, "123", "123", identity, true},
		{"explicit group", allowed, "123", "-456", identity, true},
		{"unlisted group", allowed, "123", "-999", identity, false},
		{"other bridge group", other, "123", "-456", identity, false},
		{"Bot API group", bot, "123", "-456", identity, false},
		{"inactive bridge group", inactive, "123", "-456", identity, false},
		{"missing bridge group", uuid.New(), "123", "-456", identity, false},
		{"positive mismatched DM", allowed, "123", "456", identity, false},
		{"malformed listed group", allowed, "123", "not-group", identity, false},
		{"missing sender", allowed, nil, "-456", identity, false},
		{"missing chat", allowed, "123", nil, identity, false},
		{"missing identity", allowed, "123", "-456", nil, false},
		{"missing bridge", nil, "123", "-456", identity, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := insert(tc.bridge, tc.sender, tc.chat, tc.identity)
			if tc.allowed {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "execution_origins_check5" {
				t.Fatalf("expected origin CHECK rejection, got %v", err)
			}
		})
	}
	// The predicate uses current configuration, not a permanently broadened
	// 'all negative chats' exemption. A removed allowlist is enforced immediately.
	if _, err = database.Pool().Exec(ctx, `UPDATE bridges SET settings='{}' WHERE id=$1`, allowed); err != nil {
		t.Fatal(err)
	}
	if err = insert(allowed, "123", "-456", identity); err == nil {
		t.Fatal("revoked group still accepted")
	}
	// Existing historical group origins remain present after revocation. Down
	// migration intentionally refuses their incompatible shape until removed.
	if _, err = database.Pool().Exec(ctx, `DELETE FROM execution_origins WHERE chat_id<>sender_id`); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Pool().Exec(ctx, sections[1]); err != nil {
		t.Fatal("down migration", err)
	}
	if err = insert(bot, "123", "123", identity); err != nil {
		t.Fatal("DM broken after rollback", err)
	}
	if err = insert(allowed, "123", "-456", identity); err == nil {
		t.Fatal("rollback retained group bypass")
	}
}
