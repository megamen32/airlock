package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// Poll acknowledgement is atomic with durable staging. A failed transaction
// cannot move the cursor, and replayed batches cannot re-execute completed work.
func (m *BridgeManager) stageUserbotEvents(ctx context.Context, br dbq.Bridge, events []BridgeEvent) error {
	tx, err := m.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	for _, ev := range events {
		var relay userbotEvent
		if err := json.Unmarshal(ev.RawPayload, &relay); err != nil || relay.Seq <= 0 || relay.ChatID == "" || relay.MessageID == "" || ev.BridgeID != pgUUID(br.ID) {
			return fmt.Errorf("invalid relay inbox identity")
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO userbot_inbox(bridge_id,seq,chat_id,message_id,event,is_cancel) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, br.ID, relay.Seq, relay.ChatID, relay.MessageID, payload, isCancelTap(ev))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var same bool
			err = tx.QueryRow(ctx, `SELECT event=$3::jsonb FROM userbot_inbox WHERE bridge_id=$1 AND seq=$2`, br.ID, relay.Seq, payload).Scan(&same)
			if err != nil || !same {
				return fmt.Errorf("relay identity reused with different payload")
			}
		}
	}
	if err := dbq.New(tx).UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{ID: br.ID, Config: br.Config}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (m *BridgeManager) claimUserbotEvent(ctx context.Context, br dbq.Bridge, cancel bool) (int64, BridgeEvent, error) {
	var seq int64
	var payload []byte
	err := m.db.Pool().QueryRow(ctx, `UPDATE userbot_inbox SET status='started',started_at=now() WHERE (bridge_id,seq)=(SELECT bridge_id,seq FROM userbot_inbox WHERE bridge_id=$1 AND status='pending' AND is_cancel=$2 ORDER BY seq LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING seq,event`, br.ID, cancel).Scan(&seq, &payload)
	var ev BridgeEvent
	if err == nil {
		err = json.Unmarshal(payload, &ev)
	}
	return seq, ev, err
}

func (m *BridgeManager) finishUserbotEvent(ctx context.Context, br dbq.Bridge, seq int64, runErr error) error {
	status := "completed"
	var detail *string
	if runErr != nil {
		status = "failed"
		// Store a bounded operational receipt, never a potentially credential-bearing upstream error.
		message := "Processing or delivery failed; not retried automatically."
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			status = "interrupted"
			message = "Processing interrupted; outcome may be ambiguous; not replayed."
		}
		detail = &message
	}
	_, err := m.db.Pool().Exec(ctx, `UPDATE userbot_inbox SET status=$3,error=$4,finished_at=now() WHERE bridge_id=$1 AND seq=$2 AND status='started'`, br.ID, seq, status, detail)
	return err
}

func userbotWait(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(250 * time.Millisecond):
		return true
	}
}

// One session lock protects restart recovery and the two ordered workers. A
// replacement poller waits for its predecessor to finish before classifying any
// started receipt as interrupted. Cancel requests have an independent lane.
func (m *BridgeManager) runUserbotInbox(ctx context.Context, br dbq.Bridge) {
	m.superviseUserbotInbox(ctx, br, m.HandleEvent)
}

func (m *BridgeManager) superviseUserbotInbox(ctx context.Context, br dbq.Bridge, handle func(context.Context, BridgeEvent) error) {
	for ctx.Err() == nil {
		m.runUserbotInboxOnce(ctx, br, handle)
		if !userbotWait(ctx) {
			return
		}
	}
}

func (m *BridgeManager) runUserbotInboxOnce(parent context.Context, br dbq.Bridge, handle func(context.Context, BridgeEvent) error) {
	ctx, stopWorkers := context.WithCancel(parent)
	defer stopWorkers()
	lease, err := m.db.Pool().Acquire(ctx)
	if err != nil {
		m.logger.Error("inbox lease", zap.Error(err))
		return
	}
	defer lease.Release()
	lockID := pgUUID(br.ID).String() + ":userbot-inbox"
	for {
		var locked bool
		err = lease.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, lockID).Scan(&locked)
		if err != nil {
			m.logger.Error("inbox lock", zap.Error(err))
			return
		}
		if locked {
			break
		}
		if !userbotWait(ctx) {
			return
		}
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := lease.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, lockID); err != nil {
			_ = lease.Conn().Close(cleanup)
		}
	}()
	rows, err := m.db.Pool().Query(ctx, `UPDATE userbot_inbox SET status='interrupted',error='Restart interrupted processing; not replayed.',finished_at=now() WHERE bridge_id=$1 AND status='started' RETURNING seq,event`, br.ID)
	if err != nil {
		m.logger.Error("inbox recovery", zap.Error(err))
		return
	}
	var interrupted []BridgeEvent
	for rows.Next() {
		var seq int64
		var payload []byte
		var ev BridgeEvent
		if rows.Scan(&seq, &payload) == nil && json.Unmarshal(payload, &ev) == nil {
			interrupted = append(interrupted, ev)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		m.logger.Error("inbox recovery receipts", zap.Error(err))
		return
	}
	for _, ev := range interrupted {
		m.notifyUserbotInterrupted(ctx, ev)
	}
	var workers sync.WaitGroup
	for _, cancellation := range []bool{false, true} {
		workers.Add(1)
		go func(cancellation bool) {
			defer workers.Done()
			for ctx.Err() == nil {
				seq, ev, err := m.claimUserbotEvent(ctx, br, cancellation)
				if errors.Is(err, pgx.ErrNoRows) {
					if !userbotWait(ctx) {
						return
					}
					continue
				}
				if err != nil {
					m.logger.Error("claim inbox", zap.Error(err))
					if !userbotWait(ctx) {
						return
					}
					continue
				}
				runErr := handle(ctx, ev)
				finishCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err = m.finishUserbotEvent(finishCtx, br, seq, runErr)
				cancel()
				if err != nil {
					// Stop both lanes and release the lease before recovery. The
					// supervisor marks this ambiguous event interrupted and then
					// resumes later pending events, never re-running this one.
					m.logger.Error("persist inbox outcome; restarting workers", zap.Error(err))
					stopWorkers()
					return
				}
				if runErr != nil {
					m.logger.Error("userbot processing failed; receipt retained", zap.Error(runErr))
				}
			}
		}(cancellation)
	}
	workers.Wait()
}

func (m *BridgeManager) notifyUserbotInterrupted(ctx context.Context, ev BridgeEvent) {
	// A restart notice is sent only to a still-admitted identity, never to an
	// arbitrary address recovered from the inbox. Marking interrupted precedes
	// delivery, so uncertain notifications are not replayed either.
	if _, err := auth.AdmitBridge(ctx, dbq.New(m.db.Pool()), ev.BridgeID, ev.SenderID, ev.ExternalID); err != nil {
		return
	}
	ctx = context.WithValue(ctx, relayIncomingKey{}, ev.BridgeID.String()+":"+ev.ExternalID+":restart:"+string(ev.RawPayload))
	if err := m.SendMessage(ctx, ev.BridgeID, ev.ExternalID, "Предыдущий запрос прервался при перезапуске. Я не повторял его автоматически, чтобы не выполнить действие дважды. Проверь результат перед повторной отправкой."); err != nil {
		m.logger.Warn("interrupted request notice failed; receipt retained", zap.Error(err))
	}
}
