-- name: GetAgentUserModelPreference :one
SELECT provider_id, model, updated_at
FROM agent_user_model_preferences
WHERE agent_id = $1 AND user_id = $2;

-- name: UpsertAgentUserModelPreference :one
INSERT INTO agent_user_model_preferences (agent_id, user_id, provider_id, model)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id, user_id) DO UPDATE
SET provider_id = EXCLUDED.provider_id,
    model = EXCLUDED.model,
    updated_at = now()
RETURNING provider_id, model, updated_at;

-- name: DeleteAgentUserModelPreference :exec
DELETE FROM agent_user_model_preferences
WHERE agent_id = $1 AND user_id = $2;
