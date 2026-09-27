package jobs

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RetryForAgent repairs a failed idempotent reminder without accepting a new
// execution origin from the caller. General failed side-effect jobs remain on
// the existing human-authorized retry API. The dispatcher revalidates the
// original persisted origin before the next attempt.
func (s *Service) RetryForAgent(ctx context.Context, agentID, jobID uuid.UUID) (dbq.AgentJob, error) {
	if agentID == uuid.Nil || auth.AgentIDFromContext(ctx) != agentID {
		return dbq.AgentJob{}, service.ErrUnauthorized
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agent, err := q.GetAgentByIDForUpdate(ctx, toPgUUID(agentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if auth.AgentTokenVersionFromContext(ctx) < 1 || auth.AgentTokenVersionFromContext(ctx) != agent.AgentTokenVersion || agent.Status != "active" {
		return dbq.AgentJob{}, service.ErrUnauthorized
	}
	job, err := q.GetAgentJobByIDAndAgentForUpdate(ctx, dbq.GetAgentJobByIDAndAgentForUpdateParams{ID: toPgUUID(jobID), AgentID: toPgUUID(agentID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentJob{}, service.ErrNotFound
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if job.HandlerName != "deliver_reminder" || job.HandlerVersion != 1 {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "handler is not approved for idempotent recovery")
	}
	if job.Status == "queued" || job.Status == "running" {
		return job, tx.Commit(ctx)
	}
	if job.Status != "failed" || job.AttemptCount >= manualRetryHardLimit || !job.OriginID.Valid || !job.SourceRunID.Valid {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "only failed reminders with an original execution origin can be recovered")
	}
	if agent.JobDispatchPausedBuildID.Valid {
		compatible, e := q.CandidateAgentJobContractMatches(ctx, dbq.CandidateAgentJobContractMatchesParams{BuildID: agent.JobDispatchPausedBuildID, AgentID: job.AgentID, HandlerName: job.HandlerName, HandlerVersion: job.HandlerVersion, InputSchemaHash: job.InputSchemaHash, OutputSchemaHash: job.OutputSchemaHash})
		if e != nil {
			return dbq.AgentJob{}, e
		}
		if !compatible {
			return dbq.AgentJob{}, candidateContractError(job.HandlerName, job.HandlerVersion, job.InputSchemaHash, job.OutputSchemaHash)
		}
	}
	handler, err := q.GetAgentJobHandlerForEnqueue(ctx, dbq.GetAgentJobHandlerForEnqueueParams{AgentID: job.AgentID, HandlerName: job.HandlerName, HandlerVersion: job.HandlerVersion})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "reminder handler is unavailable")
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if handler.InputSchemaHash != job.InputSchemaHash || handler.OutputSchemaHash != job.OutputSchemaHash {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "reminder handler contract changed")
	}
	active, err := q.HasActiveAgentJobAttempt(ctx, job.ID)
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if active {
		return dbq.AgentJob{}, service.Detail(service.ErrConflict, "job still has an active attempt")
	}
	job, err = q.RetryTerminalAgentJob(ctx, job.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return dbq.AgentJob{}, service.ErrConflict
	}
	if err != nil {
		return dbq.AgentJob{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return dbq.AgentJob{}, err
	}
	s.wake()
	return job, nil
}
