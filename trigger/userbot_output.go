package trigger

import (
	"context"
	"fmt"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

func (m *BridgeManager) SupportsOutputOnce(ctx context.Context, bridgeID uuid.UUID) bool {
	br, err := dbq.New(m.db.Pool()).GetBridgeByID(ctx, toPgUUID(bridgeID))
	_, ok := m.drivers["telegram_userbot"].(*UserbotDriver)
	return err == nil && br.Type == "telegram_userbot" && br.Status == "active" && ok
}

// SendPartsOnce delegates deduplication to the relay's durable receipt. An
// ambiguous transport outcome remains pending and is never silently re-sent.
func (m *BridgeManager) SendPartsOnce(ctx context.Context, bridgeID uuid.UUID, externalID, key string, parts []wire.DisplayPart) error {
	br, err := dbq.New(m.db.Pool()).GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		return err
	}
	driver, ok := m.drivers[br.Type].(*UserbotDriver)
	if !ok || br.Status != "active" || key == "" {
		return fmt.Errorf("bridge does not support keyed output")
	}
	token, err := m.encryptor.Get(ctx, "bridge/"+bridgeID.String()+"/bot_token", br.BotTokenRef)
	if err != nil {
		return err
	}
	br.BotTokenRef = token
	ctx = context.WithValue(ctx, relayIncomingKey{}, "native-output:"+key)
	return driver.SendParts(ctx, br, externalID, parts)
}
