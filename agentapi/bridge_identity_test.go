package agentapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.uber.org/zap"
)

func TestBridgeIdentityResolutionIsAgentBoundAndLive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctr, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("bridge_identity_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
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

	createUser := func(name string) pgtype.UUID {
		t.Helper()
		var id pgtype.UUID
		if err := database.Pool().QueryRow(ctx, `INSERT INTO principals(kind) VALUES('user') RETURNING id`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Pool().Exec(ctx, `INSERT INTO users(id,email,display_name,tenant_role,password_hash,oidc_sub,must_change_password,auth_epoch) VALUES($1,$2,$3,'user','hash','',false,1)`, id, name+"@example.test", name); err != nil {
			t.Fatal(err)
		}
		return id
	}
	owner := createUser("owner")
	resolved := createUser("resolved")
	missing := createUser("missing")
	ambiguous := createUser("ambiguous")
	revoked := createUser("revoked")
	foreign := createUser("foreign")
	createAgent := func(slug string) dbq.Agent {
		t.Helper()
		agent, createErr := q.CreateAgent(ctx, dbq.CreateAgentParams{Name: slug, Slug: slug, OwnerPrincipalID: owner, Config: []byte(`{}`)})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, createErr = database.Pool().Exec(ctx, `UPDATE agents SET status='active' WHERE id=$1`, agent.ID); createErr != nil {
			t.Fatal(createErr)
		}
		return agent
	}
	agent, otherAgent := createAgent("identity-one"), createAgent("identity-two")
	bridgeID, otherBridgeID := uuid.New(), uuid.New()
	insertBridge := func(id uuid.UUID, agentID pgtype.UUID) {
		t.Helper()
		_, insertErr := database.Pool().Exec(ctx, `INSERT INTO bridges(id,agent_id,owner_principal_id,type,name,bot_username,status,is_system,config,settings,bot_token_ref,managed,is_manager,manager_error) VALUES($1,$2,$3,'telegram_userbot','test','test','active',false,'{}','{"allowed_chat_ids":["-1001"]}','','false',false,'')`, id, agentID, owner)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	insertBridge(bridgeID, agent.ID)
	insertBridge(otherBridgeID, otherAgent.ID)
	link := func(user pgtype.UUID, external string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := database.Pool().QueryRow(ctx, `INSERT INTO platform_identities(user_id,platform,platform_user_id) VALUES($1,'telegram_userbot',$2) RETURNING id`, user, external).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ownerLink := link(owner, "100")
	link(resolved, "200")
	link(ambiguous, "300")
	link(ambiguous, "301")
	revokedLink := link(revoked, "400")
	link(foreign, "500")
	for _, id := range []pgtype.UUID{owner, resolved, missing, ambiguous, revoked} {
		if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: agent.ID, GranteeID: id, Role: "user"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{AgentID: otherAgent.ID, GranteeID: foreign, Role: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err = database.Pool().Exec(ctx, `DELETE FROM platform_identities WHERE id=$1`, revokedLink); err != nil {
		t.Fatal(err)
	}

	h := &Handler{db: database, logger: zap.NewNop()}
	router := chi.NewRouter()
	router.Use(auth.AgentMiddleware("test-secret", q))
	router.Post("/bridge-identities/resolve", h.ResolveBridgeIdentities)
	token, err := auth.IssueAgentToken("test-secret", uuid.UUID(agent.ID.Bytes), 1)
	if err != nil {
		t.Fatal(err)
	}
	call := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/bridge-identities/resolve", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res
	}
	body := fmt.Sprintf(`{"bridgeId":%q,"senderId":100,"chatId":-1001,"memberIds":[%q,%q,%q,%q,%q]}`, bridgeID, uuid.UUID(resolved.Bytes), uuid.UUID(missing.Bytes), uuid.UUID(ambiguous.Bytes), uuid.UUID(revoked.Bytes), uuid.UUID(foreign.Bytes))
	res := call(body)
	if res.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", res.Code, res.Body.String())
	}
	var got bridgeIdentityLookupResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Platform != "telegram_userbot" || got.SenderUserID != uuid.UUID(owner.Bytes).String() {
		t.Fatalf("wrong admitted sender: %#v", got)
	}
	wantStatuses := []string{"resolved", "missing_link", "ambiguous_link", "missing_link", "not_member"}
	for i, want := range wantStatuses {
		if got.Recipients[i].Status != want {
			t.Fatalf("recipient[%d] status=%q want=%q: %#v", i, got.Recipients[i].Status, want, got.Recipients)
		}
	}
	if got.Recipients[0].PlatformUserID != "200" || got.Recipients[2].PlatformUserID != "" {
		t.Fatalf("unsafe resolved ids: %#v", got.Recipients)
	}

	// A stale app snapshot is rejected immediately after grant removal.
	if err := q.DeleteAgentGrant(ctx, dbq.DeleteAgentGrantParams{AgentID: agent.ID, GranteeID: resolved}); err != nil {
		t.Fatal(err)
	}
	res = call(body)
	if res.Code != http.StatusOK {
		t.Fatalf("stale snapshot status=%d body=%s", res.Code, res.Body.String())
	}
	got = bridgeIdentityLookupResponse{}
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Recipients[0].Status != "not_member" || got.Recipients[0].PlatformUserID != "" {
		t.Fatalf("removed grant leaked mapping: %#v", got.Recipients[0])
	}

	if res = call(fmt.Sprintf(`{"bridgeId":%q,"senderId":100,"chatId":-1001,"memberIds":[]}`, otherBridgeID)); res.Code != http.StatusForbidden {
		t.Fatalf("cross-agent bridge status=%d body=%s", res.Code, res.Body.String())
	}
	if res = call(fmt.Sprintf(`{"bridgeId":%q,"senderId":100,"chatId":-9999,"memberIds":[]}`, bridgeID)); res.Code != http.StatusForbidden {
		t.Fatalf("cross-chat status=%d body=%s", res.Code, res.Body.String())
	}
	duplicate := uuid.UUID(missing.Bytes).String()
	if res = call(fmt.Sprintf(`{"bridgeId":%q,"senderId":100,"chatId":-1001,"memberIds":[%q,%q]}`, bridgeID, duplicate, duplicate)); res.Code != http.StatusBadRequest {
		t.Fatalf("duplicate request status=%d body=%s", res.Code, res.Body.String())
	}
	// Revoking the sender link invalidates admission instead of using a cached snapshot.
	if _, err = database.Pool().Exec(ctx, `DELETE FROM platform_identities WHERE id=$1`, ownerLink); err != nil {
		t.Fatal(err)
	}
	if res = call(fmt.Sprintf(`{"bridgeId":%q,"senderId":100,"chatId":-1001,"memberIds":[]}`, bridgeID)); res.Code != http.StatusForbidden {
		t.Fatalf("revoked sender status=%d body=%s", res.Code, res.Body.String())
	}
}
