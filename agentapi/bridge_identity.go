package agentapi

import (
	"net/http"
	"strconv"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const maxBridgeIdentityMembers = 256

type bridgeIdentityLookupRequest struct {
	BridgeID  string   `json:"bridgeId"`
	SenderID  int64    `json:"senderId"`
	ChatID    int64    `json:"chatId"`
	MemberIDs []string `json:"memberIds"`
}

type bridgeIdentityRecipient struct {
	UserID         string `json:"userId"`
	Status         string `json:"status"`
	PlatformUserID string `json:"platformUserId,omitempty"`
}

type bridgeIdentityLookupResponse struct {
	Platform     string                    `json:"platform"`
	SenderUserID string                    `json:"senderUserId"`
	Recipients   []bridgeIdentityRecipient `json:"recipients"`
}

// ResolveBridgeIdentities performs one exact, agent-bound bridge lookup. It is
// intentionally not a tenant directory: reverse lookup is limited to the
// explicit UUIDs supplied by the app and each UUID is rechecked against the
// app's current per-user grant before an external ID is returned.
func (h *Handler) ResolveBridgeIdentities(w http.ResponseWriter, r *http.Request) {
	var req bridgeIdentityLookupRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	bridgeID, err := uuid.Parse(req.BridgeID)
	if err != nil || req.SenderID <= 0 || req.ChatID == 0 || len(req.MemberIDs) > maxBridgeIdentityMembers {
		writeJSONError(w, http.StatusBadRequest, "invalid bridge identity lookup")
		return
	}
	agentID := auth.AgentIDFromContext(r.Context())
	if agentID == uuid.Nil {
		writeJSONError(w, http.StatusUnauthorized, "agent authentication required")
		return
	}

	memberIDs := make([]pgtype.UUID, len(req.MemberIDs))
	seen := make(map[uuid.UUID]struct{}, len(req.MemberIDs))
	for i, raw := range req.MemberIDs {
		id, parseErr := uuid.Parse(raw)
		if parseErr != nil || id == uuid.Nil {
			writeJSONError(w, http.StatusBadRequest, "invalid member id")
			return
		}
		if _, duplicate := seen[id]; duplicate {
			writeJSONError(w, http.StatusBadRequest, "duplicate member id")
			return
		}
		seen[id] = struct{}{}
		memberIDs[i] = pgtype.UUID{Bytes: id, Valid: true}
	}

	q := dbq.New(h.db.Pool())
	bridge, err := q.GetBridgeByID(r.Context(), pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil || bridge.Status != "active" || bridge.IsSystem ||
		!bridge.AgentID.Valid || uuid.UUID(bridge.AgentID.Bytes) != agentID {
		writeJSONError(w, http.StatusForbidden, "bridge unavailable")
		return
	}
	senderID, chatID := strconv.FormatInt(req.SenderID, 10), strconv.FormatInt(req.ChatID, 10)
	claims, err := auth.AdmitBridge(r.Context(), q, bridgeID, senderID, chatID)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "bridge identity not admitted")
		return
	}
	senderUserID, err := uuid.Parse(claims.Subject)
	if err != nil || senderUserID == uuid.Nil {
		writeJSONError(w, http.StatusForbidden, "bridge identity not admitted")
		return
	}

	rows, err := q.ResolveAgentMemberPlatformIdentities(r.Context(), dbq.ResolveAgentMemberPlatformIdentitiesParams{
		UserIds:  memberIDs,
		AgentID:  pgtype.UUID{Bytes: agentID, Valid: true},
		Platform: bridge.Type,
	})
	if err != nil {
		h.logger.Error("bridge identity lookup failed")
		writeJSONError(w, http.StatusInternalServerError, "bridge identity lookup failed")
		return
	}
	byID := make(map[uuid.UUID]dbq.ResolveAgentMemberPlatformIdentitiesRow, len(rows))
	for _, row := range rows {
		if row.UserID.Valid {
			byID[uuid.UUID(row.UserID.Bytes)] = row
		}
	}
	recipients := make([]bridgeIdentityRecipient, 0, len(memberIDs))
	for _, memberID := range memberIDs {
		id := uuid.UUID(memberID.Bytes)
		row, ok := byID[id]
		item := bridgeIdentityRecipient{UserID: id.String(), Status: "not_member"}
		if ok && row.IsMember {
			switch len(row.PlatformUserIds) {
			case 0:
				item.Status = "missing_link"
			case 1:
				item.Status = "resolved"
				item.PlatformUserID = row.PlatformUserIds[0]
			default:
				item.Status = "ambiguous_link"
			}
		}
		recipients = append(recipients, item)
	}
	writeJSON(w, http.StatusOK, bridgeIdentityLookupResponse{
		Platform: bridge.Type, SenderUserID: senderUserID.String(), Recipients: recipients,
	})
}
