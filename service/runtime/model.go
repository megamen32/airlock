package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/modelresolve"
	basesvc "github.com/airlockrun/airlock/service"
	modelssvc "github.com/airlockrun/airlock/service/models"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (h *Service) LanguageModelOptions(resolved ResolvedModel) solprovider.Options {
	opts := solprovider.Options{
		APIKey:                    resolved.ApiKey,
		BaseURL:                   resolved.BaseURL,
		IncludeUsage:              resolved.IncludeUsage,
		SupportsStructuredOutputs: resolved.SupportsStructuredOutputs,
	}
	if resolved.ProviderID == "openai-compatible" {
		opts.HTTPClient = h.httpNetwork.ProviderEndpointClient(0)
	}
	return opts
}

// resolveModel determines which provider row + model name to use for a
// request, then loads the row by FK and decrypts its API key.
//
// Precedence:
//  1. A non-empty slug names a registered agent_model_slots row:
//     - bound (assigned_provider_id + assigned_model) ⇒ use it directly
//     - unbound ⇒ resolve the default for the SLOT's declared capability,
//     not the request-supplied one (the slot owns the capability — it is
//     what the operator sees and binds in the UI)
//     An unregistered non-empty slug is a loud error: the agentsdk getters
//     require RegisterModel, so a missing row means a stale/typo'd slug, not
//     something to silently route to a default.
//  2. An empty slug is the capability-routed path used by the built-in media
//     tools (transcribe/vision/image/speech/embedding): resolve the default
//     for the request-supplied capability.
//
// Steps 1(unbound) and 2 then walk the agent's per-capability override pair,
// then the system_settings capability default pair (modelForCapability).
// Empty FK at every tier ⇒ "no model configured" error.
type ResolvedModel struct {
	Limits                    session.ModelLimits
	ProviderID                string
	ProviderSlug              string
	ModelID                   string
	ApiKey                    string
	BaseURL                   string
	IncludeUsage              *bool
	SupportsStructuredOutputs *bool
	Reasoning                 bool
}

func (h *Service) ResolveModel(ctx context.Context, agentID, slug, capability string) (ResolvedModel, error) {
	return h.resolveModel(ctx, agentID, slug, capability, uuid.Nil, authz.Principal{})
}

// ResolveModelForUser applies one caller's text-model preference to an
// invocation-bound run. Named agent model slots always take precedence.
func (h *Service) ResolveModelForUser(ctx context.Context, agentID, slug, capability string, userID uuid.UUID, principal authz.Principal) (ResolvedModel, error) {
	return h.resolveModel(ctx, agentID, slug, capability, userID, principal)
}

func (h *Service) resolveModel(ctx context.Context, agentID, slug, capability string, preferenceUserID uuid.UUID, principal authz.Principal) (ResolvedModel, error) {
	q := dbq.New(h.db.Pool())

	agentUUID, parseErr := parseUUID(agentID)
	if parseErr != nil {
		return ResolvedModel{}, fmt.Errorf("invalid agent ID: %w", parseErr)
	}
	pgAgentID := toPgUUID(agentUUID)

	var (
		providerRowID pgtype.UUID
		modelName     string
	)
	if slug == "" && normalizeCapability(capability) == "text" && preferenceUserID != uuid.Nil {
		preference, preferenceErr := q.GetAgentUserModelPreference(ctx, dbq.GetAgentUserModelPreferenceParams{
			AgentID: pgAgentID,
			UserID:  toPgUUID(preferenceUserID),
		})
		switch {
		case errors.Is(preferenceErr, pgx.ErrNoRows):
		case preferenceErr != nil:
			return ResolvedModel{}, fmt.Errorf("get caller model preference: %w", preferenceErr)
		default:
			entitlementErr := modelssvc.CheckEntitled(ctx, q, principal, preference.CatalogID, preference.Model)
			if entitlementErr == nil {
				providerRowID, modelName = preference.CatalogID, preference.Model
			} else if errors.Is(entitlementErr, basesvc.ErrForbidden) {
				// A revoked grant must restore a usable default rather than trapping
				// a caller on an inaccessible preference.
				if err := q.DeleteAgentUserModelPreference(ctx, dbq.DeleteAgentUserModelPreferenceParams{AgentID: pgAgentID, UserID: toPgUUID(preferenceUserID)}); err != nil {
					return ResolvedModel{}, fmt.Errorf("clear unavailable caller model preference: %w", err)
				}
			} else {
				return ResolvedModel{}, fmt.Errorf("check caller model preference entitlement: %w", entitlementErr)
			}
		}
	}

	if slug != "" {
		slot, slotErr := q.GetAgentModelSlot(ctx, dbq.GetAgentModelSlotParams{
			AgentID: pgAgentID,
			Slug:    slug,
		})
		switch {
		case errors.Is(slotErr, pgx.ErrNoRows):
			return ResolvedModel{}, fmt.Errorf("model slug %q is not registered for this agent — declare it with RegisterModel", slug)
		case slotErr != nil:
			return ResolvedModel{}, fmt.Errorf("look up model slot %q: %w", slug, slotErr)
		case slot.AssignedProviderID.Valid && slot.AssignedModel != "":
			providerRowID = slot.AssignedProviderID
			modelName = slot.AssignedModel
		default:
			// Declared but unbound: the slot's declared capability governs the
			// default fallback, overriding whatever capability the request
			// carried — a vision slot must never resolve via the text/exec pair.
			capability = slot.Capability
		}
	}

	if !providerRowID.Valid || modelName == "" {
		var err error
		providerRowID, modelName, err = h.ModelForCapability(ctx, q, pgAgentID, capability)
		if err != nil {
			return ResolvedModel{}, err
		}
	}
	if !providerRowID.Valid || modelName == "" {
		return ResolvedModel{}, fmt.Errorf("no model configured for capability %q — set one in admin Settings or the agent's Models tab", capability)
	}

	// Load the providers row by FK so we get the catalog provider_id and
	// API key without parsing strings.
	p, dbErr := q.GetProviderByID(ctx, providerRowID)
	if dbErr != nil {
		return ResolvedModel{}, fmt.Errorf("provider row not found: %w", dbErr)
	}
	if !p.IsEnabled {
		return ResolvedModel{}, fmt.Errorf("provider %q (%s) is disabled", p.CatalogID, p.Slug)
	}
	var includeUsage *bool
	var supportsStructuredOutputs *bool
	var limits session.ModelLimits
	var reasoning bool
	if p.CatalogID == "openai-compatible" {
		confirmed, modelErr := q.GetProviderModel(ctx, dbq.GetProviderModelParams{
			ConfiguredProviderID: p.ID,
			ModelID:              modelName,
		})
		if modelErr != nil {
			return ResolvedModel{}, fmt.Errorf("model %q is not confirmed for provider %q (%s): %w", modelName, p.CatalogID, p.Slug, modelErr)
		}
		includeUsage = &confirmed.IncludeUsage
		supportsStructuredOutputs = &confirmed.StructuredOutputs
		reasoning = confirmed.Reasoning
		limits = session.ModelLimits{Context: int(confirmed.ContextLimit), Output: int(confirmed.OutputLimit)}
	} else if info, ok := solprovider.GetModelInfo(p.CatalogID, modelName); ok && info.Limit != nil {
		limits = session.ModelLimits{Context: info.Limit.Context, Input: info.Limit.Input, Output: info.Limit.Output}
	}
	decrypted := ""
	if p.ApiKey != "" {
		decrypted, dbErr = h.encryptor.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
		if dbErr != nil {
			return ResolvedModel{}, fmt.Errorf("decrypt API key for %q (%s): %w", p.CatalogID, p.Slug, dbErr)
		}
	}
	return ResolvedModel{
		Limits:     limits,
		ProviderID: p.CatalogID, ProviderSlug: p.Slug, ModelID: modelName,
		ApiKey: decrypted, BaseURL: p.BaseUrl, IncludeUsage: includeUsage,
		SupportsStructuredOutputs: supportsStructuredOutputs,
		Reasoning:                 reasoning,
	}, nil
}

// UserTextModelPreference is a validated caller-scoped text-model choice.
type UserTextModelPreference struct {
	Model      string
	ProviderID uuid.UUID
}

// SetUserTextModel stores a caller preference only after confirming the model
// exists on the agent's text provider and is entitled for that caller.
func (h *Service) SetUserTextModel(ctx context.Context, principal authz.Principal, agentID, userID uuid.UUID, model string) (UserTextModelPreference, error) {
	model = strings.TrimSpace(model)
	if model == "" || len(model) > 120 || userID == uuid.Nil {
		return UserTextModelPreference{}, basesvc.Detail(basesvc.ErrInvalidInput, "model must contain 1..120 characters for a signed-in user")
	}
	q := dbq.New(h.db.Pool())
	pgAgentID := toPgUUID(agentID)
	providerID, _, err := h.ModelForCapability(ctx, q, pgAgentID, "text")
	if err != nil {
		return UserTextModelPreference{}, err
	}
	if !providerID.Valid {
		return UserTextModelPreference{}, basesvc.Detail(basesvc.ErrInvalidInput, "no text model provider is configured for this agent")
	}
	if _, err := q.GetProviderModel(ctx, dbq.GetProviderModelParams{ConfiguredProviderID: providerID, ModelID: model}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UserTextModelPreference{}, basesvc.Detail(basesvc.ErrInvalidInput, "model %q is not configured for this agent", model)
		}
		return UserTextModelPreference{}, fmt.Errorf("get selectable text model: %w", err)
	}
	if err := modelssvc.CheckEntitled(ctx, q, principal, providerID, model); err != nil {
		return UserTextModelPreference{}, err
	}
	row, err := q.UpsertAgentUserModelPreference(ctx, dbq.UpsertAgentUserModelPreferenceParams{
		AgentID: pgAgentID, UserID: toPgUUID(userID), CatalogID: providerID, Model: model,
	})
	if err != nil {
		return UserTextModelPreference{}, fmt.Errorf("save caller model preference: %w", err)
	}
	return UserTextModelPreference{Model: row.Model, ProviderID: uuid.UUID(row.CatalogID.Bytes)}, nil
}

// modelForCapability picks the model for a capability using the tier-2 and
// tier-3 fallbacks: per-agent override pair, then system default pair.
// Returns invalid FK + empty name when both tiers are empty so the caller
// can produce a single clear error.
func (h *Service) ModelForCapability(ctx context.Context, q *dbq.Queries, agentID pgtype.UUID, capability string) (pgtype.UUID, string, error) {
	agent, dbErr := q.GetAgentByID(ctx, agentID)
	if dbErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get agent: %w", dbErr)
	}
	if fk, name := modelresolve.AgentCapabilityOverride(agent, capability); fk.Valid && name != "" {
		return fk, name, nil
	}
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get system settings: %w", sErr)
	}
	fk, name := modelresolve.SystemCapabilityDefault(settings, capability)
	return fk, name, nil
}
