package appruntime

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/apperr"
	"github.com/google/uuid"
)

// UserTextModelPreference is the caller-scoped text model accepted by Airlock.
type UserTextModelPreference struct {
	Model      string `json:"model"`
	ProviderID string `json:"providerId"`
}

// SetCurrentUserTextModel binds a preference to the authenticated caller of an
// admitted app run; applications cannot select an arbitrary user or agent.
func (h *Service) SetCurrentUserTextModel(ctx context.Context, runID uuid.UUID, model string) (UserTextModelPreference, error) {
	admitted, err := h.ResolveRun(ctx, runID)
	if err != nil {
		return UserTextModelPreference{}, err
	}
	if admitted.Runtime.Caller.User == nil {
		return UserTextModelPreference{}, apperr.ErrForbidden
	}
	userID, err := uuid.Parse(admitted.Runtime.Caller.User.ID)
	if err != nil {
		return UserTextModelPreference{}, errors.New("runtime caller has an invalid user ID")
	}
	agentID, err := uuid.Parse(admitted.Runtime.AgentID)
	if err != nil {
		return UserTextModelPreference{}, errors.New("runtime has an invalid agent ID")
	}
	preference, err := h.runtime.SetUserTextModel(ctx, admitted.Principal, agentID, userID, model)
	if err != nil {
		return UserTextModelPreference{}, err
	}
	return UserTextModelPreference{Model: preference.Model, ProviderID: preference.ProviderID.String()}, nil
}
