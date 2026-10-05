-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION userbot_origin_chat_allowed(p_bridge uuid,p_sender text,p_chat text)
RETURNS boolean LANGUAGE sql STABLE AS $$
SELECT p_chat=p_sender OR (
  p_chat ~ '^-[1-9][0-9]*$' AND EXISTS (
    SELECT 1
    FROM bridges b
    LEFT JOIN platform_identities i
      ON i.platform=b.type AND i.platform_user_id=p_sender
    WHERE b.id=p_bridge AND b.type='telegram_userbot' AND b.status='active'
      AND ((b.settings->'allowed_chat_ids') ? p_chat
        OR (b.owner_principal_id IS NOT NULL AND i.user_id=b.owner_principal_id))
  )
);
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION userbot_origin_chat_allowed(p_bridge uuid,p_sender text,p_chat text)
RETURNS boolean LANGUAGE sql STABLE AS $$
SELECT p_chat=p_sender OR (
  p_chat ~ '^-[0-9]+$' AND EXISTS (
    SELECT 1 FROM bridges b WHERE b.id=p_bridge AND b.type='telegram_userbot'
      AND b.status='active' AND (b.settings->'allowed_chat_ids') ? p_chat
  )
);
$$;
-- +goose StatementEnd
