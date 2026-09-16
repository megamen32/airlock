package appruntime

import (
	"context"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// MutateMember uses only the agent and human principal of the authenticated
// invocation. Request bodies cannot select another app or certify an identity.
func (h *Service) MutateMember(ctx context.Context, runID uuid.UUID, userID string, remove bool) error {
	admitted, err := h.ResolveRun(ctx, runID)
	if err != nil {
		return err
	}
	if admitted.Runtime.Caller.User == nil {
		return apperr.ErrForbidden
	}
	agentID, err := parseUUID(admitted.Runtime.AgentID)
	if err != nil {
		return err
	}
	target, err := parseUUID(userID)
	if err != nil {
		return err
	}
	if target == authz.GroupUser {
		return apperr.ErrInvalidInput
	}
	// Serialize with the existing members service on the same app row. The
	// group-access check and revoke must observe a single membership state.
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}
	if err := authz.Authorize(ctx, q, admitted.Principal, authz.AgentMembersManage, agentID); err != nil {
		return err
	}
	if _, err := q.GetUserByID(ctx, toPgUUID(target)); err != nil {
		return apperr.ErrInvalidInput
	}
	if remove && pgUUID(agent.OwnerPrincipalID) == target {
		return apperr.Detail(apperr.ErrInvalidInput, "cannot remove agent owner")
	}
	roster, err := q.ListAgentGrants(ctx, toPgUUID(agentID))
	if err != nil {
		return err
	}
	for _, member := range roster {
		if remove && member.Kind == "group" {
			return apperr.Detail(apperr.ErrConflict, "remove shared group access before revoking an individual member")
		}
		if !remove && pgUUID(member.GranteeID) == target {
			// Adding a member must not demote an existing administrator.
			return nil
		}
	}
	if remove {
		err = q.DeleteAgentGrant(ctx, dbq.DeleteAgentGrantParams{AgentID: toPgUUID(agentID), GranteeID: toPgUUID(target)})
	} else {
		err = q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: toPgUUID(agentID), GranteeID: toPgUUID(target), Role: "user"})
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
