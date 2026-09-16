package appruntime

import (
	"context"
	"strings"
	"time"

	"github.com/airlockrun/airlock/apperr"
	"github.com/google/uuid"
)

// PersonHistoryQuery addresses the native sequence namespace only. Legacy
// sequence numbers require an explicit migration mapping, never reinterpretation.
type PersonHistoryQuery struct {
	Limit          int    `json:"limit,omitempty"`
	FromSeq        int64  `json:"fromSeq,omitempty"`
	ToSeq          int64  `json:"toSeq,omitempty"`
	SinceTime      string `json:"sinceTime,omitempty"`
	ConversationID string `json:"conversationId,omitempty"`
	CompletedOnly  bool   `json:"completedOnly,omitempty"`
}
type PersonHistoryMessage struct {
	ID             string    `json:"id"`
	Seq            int64     `json:"seq"`
	ConversationID string    `json:"conversationId"`
	RunID          string    `json:"runId,omitempty"`
	Role           string    `json:"role"`
	Content        string    `json:"content"`
	CreatedAt      time.Time `json:"createdAt"`
}
type PersonHistoryResponse struct {
	Scope             string                 `json:"scope"`
	SequenceNamespace string                 `json:"sequenceNamespace"`
	Messages          []PersonHistoryMessage `json:"messages"`
}

func validatePersonHistoryQuery(q *PersonHistoryQuery) (time.Time, error) {
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > 200 || q.FromSeq < 0 || q.ToSeq < 0 || (q.ToSeq != 0 && q.FromSeq > q.ToSeq) {
		return time.Time{}, apperr.Detail(apperr.ErrInvalidInput, "invalid history limit or sequence range")
	}
	if q.ConversationID != "" {
		id, err := uuid.Parse(q.ConversationID)
		if err != nil || id == uuid.Nil {
			return time.Time{}, apperr.ErrInvalidInput
		}
	}
	if q.SinceTime == "" {
		return time.Time{}, nil
	}
	since, err := time.Parse(time.RFC3339, q.SinceTime)
	if err != nil {
		return time.Time{}, apperr.Detail(apperr.ErrInvalidInput, "sinceTime must be RFC3339")
	}
	return since, nil
}

// personHistorySQL reads the raw archive, intentionally ignoring compaction
// checkpoints. The authenticated person and admitted agent are mandatory SQL
// predicates, including when a caller supplies a conversation filter.
const personHistorySQL = `
SELECT id::text, seq, conversation_id::text, COALESCE(run_id::text,''), role, visible, created_at
FROM (
 SELECT m.id, m.seq, m.conversation_id, m.run_id, m.role, m.created_at,
 COALESCE(NULLIF(btrim(m.content), ''),
   (SELECT string_agg(p->>'text', E'\n' ORDER BY ordinal)
    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(m.parts)='array' THEN m.parts ELSE '[]'::jsonb END)
      WITH ORDINALITY AS part(p, ordinal)
    WHERE p->>'type'='text' AND btrim(COALESCE(p->>'text','')) <> ''), '') AS visible
 FROM agent_messages m JOIN agent_conversations c ON c.id=m.conversation_id
 WHERE c.agent_id=$1::uuid AND c.user_id=$2::uuid
 AND c.source IN ('web','bridge')
 AND m.role IN ('user','assistant')
 AND (NOT m.ephemeral OR m.source IN ('notification','upload'))
 AND m.source IN ('','user','web','bridge','app','notification','upload')
 AND (NOT $8::boolean OR EXISTS (
   SELECT 1 FROM runs r WHERE r.id=m.run_id AND r.agent_id=c.agent_id
   AND r.caller_user_id=c.user_id AND r.caller_conversation_id=c.id AND r.status='success'
 ))
 AND ($3::bigint=0 OR m.seq >= $3) AND ($4::bigint=0 OR m.seq <= $4)
 AND ($5::timestamptz IS NULL OR m.created_at >= $5)
 AND ($6::text='' OR c.id::text=$6)
) visible_messages
WHERE btrim(visible)<>''
ORDER BY seq DESC LIMIT $7`

func (h *Service) SessionLoadPerson(ctx context.Context, runID uuid.UUID, query PersonHistoryQuery) (PersonHistoryResponse, error) {
	since, err := validatePersonHistoryQuery(&query)
	if err != nil {
		return PersonHistoryResponse{}, err
	}
	admitted, err := h.ResolveRun(ctx, runID)
	if err != nil {
		return PersonHistoryResponse{}, err
	}
	if admitted.Runtime.Caller.User == nil {
		return PersonHistoryResponse{}, apperr.ErrForbidden
	}
	userID, err := uuid.Parse(admitted.Runtime.Caller.User.ID)
	if err != nil || userID == uuid.Nil {
		return PersonHistoryResponse{}, apperr.ErrForbidden
	}
	agentID, err := uuid.Parse(admitted.Runtime.AgentID)
	if err != nil || agentID == uuid.Nil {
		return PersonHistoryResponse{}, apperr.ErrForbidden
	}
	var sinceArg any
	if !since.IsZero() {
		sinceArg = since
	}
	rows, err := h.db.Pool().Query(ctx, personHistorySQL, agentID, userID, query.FromSeq, query.ToSeq, sinceArg, strings.ToLower(query.ConversationID), query.Limit, query.CompletedOnly)
	if err != nil {
		return PersonHistoryResponse{}, err
	}
	defer rows.Close()
	out := PersonHistoryResponse{Scope: "person_same_agent", SequenceNamespace: "airlock_native", Messages: []PersonHistoryMessage{}}
	for rows.Next() {
		var m PersonHistoryMessage
		if err := rows.Scan(&m.ID, &m.Seq, &m.ConversationID, &m.RunID, &m.Role, &m.Content, &m.CreatedAt); err != nil {
			return PersonHistoryResponse{}, err
		}
		out.Messages = append(out.Messages, m)
	}
	if err := rows.Err(); err != nil {
		return PersonHistoryResponse{}, err
	}
	// Select the latest bounded tail, then present it in chronological order.
	for i, j := 0, len(out.Messages)-1; i < j; i, j = i+1, j-1 {
		out.Messages[i], out.Messages[j] = out.Messages[j], out.Messages[i]
	}
	return out, nil
}
