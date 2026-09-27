package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	jobssvc "github.com/airlockrun/airlock/service/jobs"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"
)

func TestAgentReminderRetryPreservesOriginAndOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("job_retry_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatal(err)
	}
	defer ctr.Terminate(context.Background())
	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.RunMigrations(dsn); err != nil {
		t.Fatal(err)
	}
	database := db.New(ctx, dsn)
	defer database.Close()
	q := dbq.New(database.Pool())
	var owner pgtype.UUID
	if err = database.Pool().QueryRow(ctx, `INSERT INTO principals(kind) VALUES('user') RETURNING id`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	makeAgent := func(slug string) dbq.Agent {
		a, e := q.CreateAgent(ctx, dbq.CreateAgentParams{Name: slug, Slug: slug, OwnerPrincipalID: owner, Config: []byte(`{}`)})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = database.Pool().Exec(ctx, `UPDATE agents SET status='active' WHERE id=$1`, a.ID); e != nil {
			t.Fatal(e)
		}
		return a
	}
	agent, other := makeAgent("retry-one"), makeAgent("retry-two")
	origin := uuid.New()
	if _, err = database.Pool().Exec(ctx, `INSERT INTO execution_origins(id,agent_id,ingress,actor,credential_profile,created_at) VALUES($1,$2,'web','anonymous','none',now())`, origin, agent.ID); err != nil {
		t.Fatal(err)
	}
	run, err := q.CreateRun(ctx, dbq.CreateRunParams{AgentID: agent.ID, OriginID: pgtype.UUID{Bytes: origin, Valid: true}, ExecutionKind: "prompt", InputPayload: []byte(`{}`), TriggerType: "manual", CallerAccess: "user"})
	if err != nil {
		t.Fatal(err)
	}
	hash := strings.Repeat("a", 64)
	_, err = database.Pool().Exec(ctx, `INSERT INTO agent_job_handlers(agent_id,name,version,description,timeout_ms,max_attempts,max_concurrency,input_schema,output_schema,input_schema_hash,output_schema_hash,agent_token_version,active) VALUES($1,'deliver_reminder',1,'test',10000,1,1,'{}','{}',$2,$2,1,true)`, agent.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	job := uuid.New()
	_, err = database.Pool().Exec(ctx, `INSERT INTO agent_jobs(id,agent_id,handler_name,handler_version,input_schema_hash,output_schema_hash,source_run_id,initiator_kind,initiator_access,status,timeout_ms,max_attempts,attempt_limit,attempt_count,next_attempt_at,input_payload,state_version,origin_id,completed_at,last_error) VALUES($1,$2,'deliver_reminder',1,$3,$3,$4,'system','user','failed',10000,1,1,1,now(),'{"reminderId":"fixed","userId":"original"}',1,$5,now(),'test failure')`, job, agent.ID, hash, run.ID, origin)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{jobs: jobssvc.New(database, func() {}, zap.NewNop())}
	router := chi.NewRouter()
	router.Use(auth.AgentMiddleware("test-secret", q))
	router.Post("/jobs/{jobID}/retry", h.RetryJob)
	call := func(a dbq.Agent, id uuid.UUID, body string) int {
		token, e := auth.IssueAgentToken("test-secret", uuid.UUID(a.ID.Bytes), 1)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(http.MethodPost, "/jobs/"+id.String()+"/retry", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code == 200 {
			var result struct{ Job struct{ ID, Status string } }
			if e = json.Unmarshal(w.Body.Bytes(), &result); e != nil || result.Job.ID != id.String() {
				t.Fatalf("bad retry response %s", w.Body.String())
			}
		}
		return w.Code
	}
	if got := call(other, job, "{}"); got != 404 {
		t.Fatalf("foreign job=%d", got)
	}
	if got := call(agent, uuid.New(), "{}"); got != 404 {
		t.Fatalf("absent job=%d", got)
	}
	if got := call(agent, job, `{"sourceRunId":"replacement"}`); got != 400 {
		t.Fatalf("origin override=%d", got)
	}
	if _, err = database.Pool().Exec(ctx, `INSERT INTO agent_job_attempts(job_id,attempt_number,status,runtime_generation,lease_owner,lease_token,lease_expires_at,leased_at) VALUES($1,1,'leased',1,gen_random_uuid(),gen_random_uuid(),now()+interval '1 minute',now())`, job); err != nil {
		t.Fatal(err)
	}
	if got := call(agent, job, "{}"); got != 409 {
		t.Fatalf("active ambiguous attempt retried=%d", got)
	}
	if _, err = database.Pool().Exec(ctx, `DELETE FROM agent_job_attempts WHERE job_id=$1`, job); err != nil {
		t.Fatal(err)
	}
	if got := call(agent, job, "{}"); got != 200 {
		t.Fatalf("failed retry=%d", got)
	}
	retried, err := q.GetAgentJobByID(ctx, pgtype.UUID{Bytes: job, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if retried.Status != "queued" || retried.SourceRunID != run.ID || retried.OriginID.Bytes != origin || string(retried.InputPayload) != `{"userId": "original", "reminderId": "fixed"}` {
		t.Fatalf("retry changed origin/input: status=%s source=%v origin=%v input=%s", retried.Status, retried.SourceRunID, retried.OriginID, retried.InputPayload)
	}
	if got := call(agent, job, "{}"); got != 200 {
		t.Fatalf("queued retry not noop=%d", got)
	}
	again, _ := q.GetAgentJobByID(ctx, pgtype.UUID{Bytes: job, Valid: true})
	if again.StateVersion != retried.StateVersion {
		t.Fatal("queued no-op mutated state")
	}
	if _, err = database.Pool().Exec(ctx, `UPDATE agent_jobs SET status='running',started_at=now() WHERE id=$1`, job); err != nil {
		t.Fatal(err)
	}
	if got := call(agent, job, "{}"); got != 200 {
		t.Fatalf("running retry not noop=%d", got)
	}
	for _, status := range []string{"succeeded", "cancelled"} {
		if _, err = database.Pool().Exec(ctx, `UPDATE agent_jobs SET status=$2,completed_at=now(),output_payload=CASE WHEN $2='succeeded' THEN '{}'::jsonb ELSE NULL END,cancel_requested_at=CASE WHEN $2='cancelled' THEN now() ELSE NULL END WHERE id=$1`, job, status); err != nil {
			t.Fatal(err)
		}
		if got := call(agent, job, "{}"); got != 409 {
			t.Fatalf("terminal %s retried=%d", status, got)
		}
	}
	if _, err = database.Pool().Exec(ctx, `UPDATE agent_jobs SET status='failed',last_error='test failure',input_schema_hash=$2 WHERE id=$1`, job, strings.Repeat("b", 64)); err != nil {
		t.Fatal(err)
	}
	if got := call(agent, job, "{}"); got != 409 {
		t.Fatalf("changed handler contract accepted=%d", got)
	}
	if _, err = database.Pool().Exec(ctx, `UPDATE agents SET agent_token_version=2 WHERE id=$1`, agent.ID); err != nil {
		t.Fatal(err)
	}
	if got := call(agent, job, "{}"); got != 401 {
		t.Fatalf("stale runtime accepted=%d", got)
	}
}
