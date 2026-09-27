-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION userbot_origin_chat_allowed(p_bridge uuid,p_sender text,p_chat text)
RETURNS boolean LANGUAGE sql STABLE AS $$
SELECT p_chat=p_sender OR (
  p_chat ~ '^-[0-9]+$' AND EXISTS (
    SELECT 1 FROM bridges b WHERE b.id=p_bridge AND b.type='telegram_userbot'
      AND b.status='active' AND (b.settings->'allowed_chat_ids') ? p_chat
  )
);
$$;
-- +goose StatementEnd
ALTER TABLE execution_origins DROP CONSTRAINT execution_origins_check5;
ALTER TABLE execution_origins ADD CONSTRAINT execution_origins_check5 CHECK (
  credential_profile <> 'bridge' OR (
    ingress='bridge' AND bridge_id IS NOT NULL AND platform_identity_id IS NOT NULL
    AND sender_id IS NOT NULL AND chat_id IS NOT NULL
    AND userbot_origin_chat_allowed(bridge_id,sender_id,chat_id)
  )
);

-- +goose Down
ALTER TABLE execution_origins DROP CONSTRAINT execution_origins_check5;
ALTER TABLE execution_origins ADD CONSTRAINT execution_origins_check5 CHECK (
  credential_profile <> 'bridge' OR (
    ingress='bridge' AND bridge_id IS NOT NULL AND platform_identity_id IS NOT NULL
    AND sender_id IS NOT NULL AND chat_id IS NOT NULL AND chat_id=sender_id
  )
);
DROP FUNCTION userbot_origin_chat_allowed(uuid,text,text);
