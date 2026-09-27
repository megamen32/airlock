package bridgeevents

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type groupAdmissionRow func(...any) error

func (r groupAdmissionRow) Scan(out ...any) error { return r(out...) }

type noGroupGrants struct{ pgx.Rows }

func (noGroupGrants) Next() bool { return false }
func (noGroupGrants) Err() error { return nil }
func (noGroupGrants) Close()     {}

type groupAdmissionDB struct {
	bridge, agent, user, identity uuid.UUID
	sender                        string
	allowed                       bool
}

func (d *groupAdmissionDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected mutation")
}
func (d *groupAdmissionDB) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if strings.Contains(sql, "ListAgentGrantsForGrantees") {
		return noGroupGrants{}, nil
	}
	return nil, fmt.Errorf("unexpected query")
}
func (d *groupAdmissionDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	return groupAdmissionRow(func(out ...any) error {
		put := func(i int, id uuid.UUID) { *out[i].(*pgtype.UUID) = pgtype.UUID{Bytes: id, Valid: true} }
		switch {
		case strings.Contains(sql, "name: GetBridgeByID"):
			if args[0].(pgtype.UUID).Bytes != d.bridge {
				return pgx.ErrNoRows
			}
			put(0, d.bridge)
			put(1, d.agent)
			*out[3].(*string) = "telegram_userbot"
			*out[6].(*string) = "active"
			if d.allowed {
				*out[9].(*[]byte) = []byte(`{"allowed_chat_ids":["-456"]}`)
			} else {
				*out[9].(*[]byte) = []byte(`{}`)
			}
		case strings.Contains(sql, "name: GetPlatformIdentity"):
			if args[0].(string) != "telegram_userbot" || args[1].(string) != d.sender {
				return pgx.ErrNoRows
			}
			put(0, d.identity)
			put(1, d.user)
		case strings.Contains(sql, "name: GetUserByID"):
			put(0, d.user)
			*out[3].(*string) = "user"
			*out[9].(*int64) = 1
		default:
			return fmt.Errorf("unexpected query")
		}
		return nil
	})
}

func TestUserbotGroupPromptRevalidatesActualSender(t *testing.T) {
	d := &groupAdmissionDB{bridge: uuid.New(), agent: uuid.New(), user: uuid.New(), identity: uuid.New(), sender: "123", allowed: true}
	q := dbq.New(d)
	base := context.Background()
	claims, err := auth.AdmitBridge(base, q, d.bridge, "123", "-456")
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithBridgeIdentity(base, claims)
	p, err := AdmitPrompt(ctx, q, d.agent, d.bridge, d.user, "-456")
	if err != nil || p.UserID != d.user {
		t.Fatalf("approved sender/group cannot prompt: %v", err)
	}
	if _, err = AdmitPrompt(base, q, d.agent, d.bridge, d.user, "-456"); err == nil {
		t.Fatal("group admitted without sender credential")
	}
	if _, err = AdmitPrompt(ctx, q, d.agent, d.bridge, d.user, "-789"); err == nil {
		t.Fatal("credential repointed to another group")
	}
	if _, err = AdmitPrompt(ctx, q, d.agent, d.bridge, uuid.New(), "-456"); err == nil {
		t.Fatal("credential repointed to another user")
	}
	d.sender = "999"
	if _, err = AdmitPrompt(ctx, q, d.agent, d.bridge, d.user, "-456"); err == nil {
		t.Fatal("unlinked original sender retained prompt authority")
	}
	d.sender = "123"
	d.allowed = false
	if _, err = AdmitPrompt(ctx, q, d.agent, d.bridge, d.user, "-456"); err == nil {
		t.Fatal("revoked group retained prompt authority")
	}
}
