-- +goose Up
CREATE TABLE userbot_inbox (
    bridge_id uuid NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
    seq bigint NOT NULL CHECK (seq > 0),
    chat_id text NOT NULL,
    message_id text NOT NULL,
    event jsonb NOT NULL,
    is_cancel boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','started','completed','failed','interrupted')),
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    PRIMARY KEY (bridge_id, seq),
    UNIQUE (bridge_id, chat_id, message_id)
);
CREATE INDEX userbot_inbox_pending ON userbot_inbox(bridge_id, is_cancel, seq) WHERE status = 'pending';

-- +goose Down
DROP TABLE userbot_inbox;
