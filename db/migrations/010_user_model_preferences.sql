-- +goose Up
-- A personal text-model choice belongs to one caller inside one agent. It is
-- intentionally separate from the agent-wide execution model.
CREATE TABLE agent_user_model_preferences (
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model text NOT NULL CHECK (btrim(model) <> ''),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, user_id)
);

CREATE INDEX agent_user_model_preferences_provider_idx
    ON agent_user_model_preferences (provider_id, model);

-- +goose Down
DROP TABLE agent_user_model_preferences;
