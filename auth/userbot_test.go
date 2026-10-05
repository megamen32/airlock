package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type userbotRow func(...any) error

func (r userbotRow) Scan(dest ...any) error { return r(dest...) }

type userbotDB struct {
	bridge   dbq.Bridge
	linked   dbq.PlatformIdentity
	user     dbq.User
	missing  bool
	platform string
}

func (d *userbotDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected mutation")
}
func (d *userbotDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected query")
}
func (d *userbotDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return userbotRow(func(out ...any) error {
		switch {
		case strings.Contains(sql, "name: GetBridgeByID"):
			*out[0].(*pgtype.UUID) = d.bridge.ID
			*out[1].(*pgtype.UUID) = d.bridge.AgentID
			*out[2].(*pgtype.UUID) = d.bridge.OwnerPrincipalID
			*out[3].(*string) = d.bridge.Type
			*out[6].(*string) = d.bridge.Status
			*out[7].(*bool) = d.bridge.IsSystem
			*out[9].(*[]byte) = d.bridge.Settings
		case strings.Contains(sql, "name: GetPlatformIdentity"):
			d.platform = args[0].(string)
			if d.missing {
				return pgx.ErrNoRows
			}
			*out[0].(*pgtype.UUID) = d.linked.ID
			*out[1].(*pgtype.UUID) = d.linked.UserID
		case strings.Contains(sql, "name: GetUserByID"):
			*out[0].(*pgtype.UUID) = d.user.ID
			*out[1].(*string) = d.user.Email
			*out[2].(*string) = d.user.DisplayName
			*out[3].(*string) = d.user.TenantRole
			*out[6].(*bool) = d.user.MustChangePassword
			*out[9].(*int64) = d.user.AuthEpoch
		default:
			return fmt.Errorf("unexpected query")
		}
		return nil
	})
}
func userbotAuthFixture() (*userbotDB, *dbq.Queries) {
	id := func() pgtype.UUID { return pgtype.UUID{Bytes: uuid.New(), Valid: true} }
	userID := id()
	d := &userbotDB{bridge: dbq.Bridge{ID: id(), AgentID: id(), OwnerPrincipalID: userID, Type: "telegram_userbot", Status: "active", Settings: []byte(`{"allowed_chat_ids":["-456"]}`)}, linked: dbq.PlatformIdentity{ID: id(), UserID: userID}, user: dbq.User{ID: userID, TenantRole: "user", AuthEpoch: 1}}
	return d, dbq.New(d)
}

func TestUserbotOwnerGroupAdmissionDoesNotWidenMemberAllowlist(t *testing.T) {
	d, q := userbotAuthFixture()
	bridgeID := uuid.UUID(d.bridge.ID.Bytes)
	if _, err := AdmitBridge(context.Background(), q, bridgeID, "123", "-999"); err == nil {
		t.Fatal("ordinary admission bypassed static groups")
	}
	claims, err := AdmitUserbotOwnerGroup(context.Background(), q, bridgeID, "123", "-999")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = claims.identity.Resolve(context.Background(), q); err != nil {
		t.Fatal("owner invocation did not survive live revalidation", err)
	}
	d.bridge.OwnerPrincipalID.Bytes = uuid.New()
	if _, err = AdmitUserbotOwnerGroup(context.Background(), q, bridgeID, "123", "-999"); err == nil {
		t.Fatal("linked non-owner received any-group authority")
	}
	if _, err = claims.identity.Resolve(context.Background(), q); err == nil {
		t.Fatal("revoked owner retained any-group authority")
	}
	d, q = userbotAuthFixture()
	d.bridge.Type = "telegram"
	if _, err = AdmitUserbotOwnerGroup(context.Background(), q, uuid.UUID(d.bridge.ID.Bytes), "123", "-999"); err == nil {
		t.Fatal("Bot API bridge received userbot owner-group authority")
	}
}
func TestUserbotAdmissionUsesPlatformIdentityAndExplicitGroups(t *testing.T) {
	d, q := userbotAuthFixture()
	for _, chat := range []string{"123", "-456"} {
		claims, err := AdmitBridge(context.Background(), q, uuid.UUID(d.bridge.ID.Bytes), "123", chat)
		if err != nil || claims.Subject != uuid.UUID(d.user.ID.Bytes).String() {
			t.Fatalf("admission failed %v", err)
		}
		if d.platform != "telegram_userbot" {
			t.Fatal("wrong platform namespace")
		}
	}
	for _, chat := range []string{"999", "-789"} {
		if _, err := AdmitBridge(context.Background(), q, uuid.UUID(d.bridge.ID.Bytes), "123", chat); err == nil {
			t.Fatal("unowned group/DM accepted")
		}
	}
	d.bridge.Type = "telegram"
	if _, err := AdmitBridge(context.Background(), q, uuid.UUID(d.bridge.ID.Bytes), "123", "-456"); err == nil {
		t.Fatal("Bot API group bypassed DM contract")
	}
}
func TestUserbotIdentityRevalidatesRevocations(t *testing.T) {
	for _, name := range []string{"unlinked", "disabled bridge", "changed identity", "changed user", "changed epoch", "password reset", "changed group"} {
		t.Run(name, func(t *testing.T) {
			d, q := userbotAuthFixture()
			claims, err := AdmitBridge(context.Background(), q, uuid.UUID(d.bridge.ID.Bytes), "123", "-456")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "unlinked":
				d.missing = true
			case "disabled bridge":
				d.bridge.Status = "disabled"
			case "changed identity":
				d.linked.ID.Bytes = uuid.New()
			case "changed user":
				d.user.ID.Bytes = uuid.New()
			case "changed epoch":
				d.user.AuthEpoch++
			case "password reset":
				d.user.MustChangePassword = true
			case "changed group":
				d.bridge.Settings = []byte(`{}`)
			}
			if _, err := claims.identity.Resolve(context.Background(), q); err == nil {
				t.Fatal("revoked identity remained usable")
			}
		})
	}
}
