-- +goose Up
ALTER TABLE bridges DROP CONSTRAINT bridges_type_check;
ALTER TABLE bridges ADD CONSTRAINT bridges_type_check CHECK(type IN ('telegram','telegram_userbot'));

-- +goose Down
ALTER TABLE bridges DROP CONSTRAINT bridges_type_check;
ALTER TABLE bridges ADD CONSTRAINT bridges_type_check CHECK(type = 'telegram');
