package auth

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func allowedUserbotGroup(settings []byte, chatID string) bool {
	if !strings.HasPrefix(chatID, "-") {
		return false
	}
	var cfg struct {
		Groups []string `json:"allowed_chat_ids"`
	}
	if json.Unmarshal(settings, &cfg) != nil {
		return false
	}
	for _, id := range cfg.Groups {
		if id == chatID {
			return true
		}
	}
	return false
}

type bridgeCredential struct {
	bridgeID   uuid.UUID
	senderID   string
	chatID     string
	identityID uuid.UUID
	agentID    pgtype.UUID
	system     bool
}

type admittedBridgeContextKey struct{}

// WithBridgeIdentity propagates only a server-admitted bridge credential; the
// sender cannot be substituted by a user UUID or request argument.
func WithBridgeIdentity(ctx context.Context, claims *Claims) context.Context {
	if claims == nil || claims.Identity() == nil || claims.Identity().bridge == nil {
		return ctx
	}
	return context.WithValue(ctx, admittedBridgeContextKey{}, claims.Identity())
}

func AdmitBridgeConversation(ctx context.Context, q *dbq.Queries, bridgeID uuid.UUID, chatID string) (*Claims, error) {
	if identity, ok := ctx.Value(admittedBridgeContextKey{}).(*Identity); ok {
		if identity.bridge == nil || identity.bridge.bridgeID != bridgeID || identity.bridge.chatID != chatID {
			return nil, apperr.ErrUnauthorized
		}
		return identity.Resolve(ctx, q)
	}
	return AdmitBridge(ctx, q, bridgeID, chatID, chatID)
}

// AdmitBridge admits a private message received by Airlock's authenticated
// Telegram poller. A transport supplies platform coordinates, never an Airlock
// user UUID or role. Linked identity and account state are resolved live.
func AdmitBridge(ctx context.Context, q *dbq.Queries, bridgeID uuid.UUID, senderID, chatID string) (*Claims, error) {
	if q == nil {
		panic("auth: bridge admission queries are required")
	}
	if bridgeID == uuid.Nil || senderID == "" || chatID == "" {
		return nil, apperr.ErrUnauthorized
	}
	bridge, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil || bridge.Status != "active" || (bridge.Type != "telegram" && bridge.Type != "telegram_userbot") {
		return nil, apperr.ErrUnauthorized
	}
	if chatID != senderID {
		if bridge.Type != "telegram_userbot" || !allowedUserbotGroup(bridge.Settings, chatID) {
			return nil, apperr.ErrUnauthorized
		}
	}
	linked, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{Platform: bridge.Type, PlatformUserID: senderID})
	if err != nil || !linked.UserID.Valid || uuid.UUID(linked.UserID.Bytes) == uuid.Nil {
		return nil, apperr.ErrUnauthorized
	}
	user, err := q.GetUserByID(ctx, linked.UserID)
	if err != nil || !Role(user.TenantRole).Valid() {
		return nil, apperr.ErrUnauthorized
	}
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: uuid.UUID(user.ID.Bytes).String()},
		Email:            user.Email, DisplayName: user.DisplayName, TenantRole: user.TenantRole,
		AuthEpoch: user.AuthEpoch, MustChangePassword: user.MustChangePassword,
	}
	if err := RequireSecuredAccount(claims); err != nil {
		return nil, err
	}
	claims.identity = &Identity{claims: *claims, bridge: &bridgeCredential{bridgeID: bridgeID, senderID: senderID, chatID: chatID, identityID: uuid.UUID(linked.ID.Bytes), agentID: bridge.AgentID, system: bridge.IsSystem}}
	return claims, nil
}
