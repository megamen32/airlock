package appruntime

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestPersonHistoryQueryValidation(t *testing.T) {
	for _, q := range []PersonHistoryQuery{{Limit: 201}, {FromSeq: -1}, {FromSeq: 5, ToSeq: 2}, {SinceTime: "yesterday"}, {ConversationID: "not-uuid"}} {
		if _, err := validatePersonHistoryQuery(&q); err == nil {
			t.Fatalf("accepted %+v", q)
		}
	}
	q := PersonHistoryQuery{}
	if _, err := validatePersonHistoryQuery(&q); err != nil || q.Limit != 50 {
		t.Fatalf("default=%+v %v", q, err)
	}
}

// Exercise the actual production SQL against an isolated database. This proves
// ownership also applies to explicitly selected conversations and sequences.
func TestPersonHistorySQLRejectsCrossUserAndNonInteractiveRecords(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	container, err := postgres.Run(ctx, "postgres:17-alpine", postgres.WithDatabase("history_test"), postgres.WithUsername("test"), postgres.WithPassword("test"), postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatal(err)
	}
	defer container.Terminate(context.Background())
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, `CREATE TABLE agent_conversations(id uuid,agent_id uuid,user_id uuid,source text);
 CREATE TABLE agent_messages(id uuid,seq bigint,conversation_id uuid,role text,source text,content text,parts jsonb,ephemeral bool,created_at timestamptz);
 INSERT INTO agent_conversations VALUES
 ('00000000-0000-0000-0000-000000000001','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','web'),
 ('00000000-0000-0000-0000-000000000002','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','bridge'),
 ('00000000-0000-0000-0000-000000000003','11111111-1111-1111-1111-111111111111','33333333-3333-3333-3333-333333333333','web'),
 ('00000000-0000-0000-0000-000000000004','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','delegated'),
 ('00000000-0000-0000-0000-000000000005','55555555-5555-5555-5555-555555555555','22222222-2222-2222-2222-222222222222','web');
 INSERT INTO agent_messages
 SELECT gen_random_uuid(),i,c.id,'user','','text-'||i,'[]',false,now()
 FROM agent_conversations c CROSS JOIN LATERAL (SELECT right(c.id::text,1)::bigint AS i) x;
 INSERT INTO agent_messages VALUES
 (gen_random_uuid(),6,'00000000-0000-0000-0000-000000000001','tool','','tool-secret','[]',false,now()),
 (gen_random_uuid(),7,'00000000-0000-0000-0000-000000000001','assistant','compaction','summary-private','[]',false,now()),
 (gen_random_uuid(),8,'00000000-0000-0000-0000-000000000001','assistant','','','[{"type":"reasoning","text":"reasoning-secret"},{"type":"text","text":"visible-reply"}]',false,now()),
 (gen_random_uuid(),9,'00000000-0000-0000-0000-000000000001','assistant','llm','model-only-secret','[]',false,now());
 ALTER TABLE agent_messages ADD COLUMN run_id uuid;
 CREATE TABLE runs(id uuid,agent_id uuid,caller_user_id uuid,caller_conversation_id uuid,status text);
 INSERT INTO runs VALUES
 ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','00000000-0000-0000-0000-000000000001','success'),
 ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222','00000000-0000-0000-0000-000000000001','running');
 INSERT INTO agent_messages(id,seq,conversation_id,role,source,content,parts,ephemeral,created_at,run_id) VALUES
 (gen_random_uuid(),10,'00000000-0000-0000-0000-000000000001','user','user','completed-question','[]',false,now(),'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
 (gen_random_uuid(),11,'00000000-0000-0000-0000-000000000001','assistant','user','completed-answer','[]',false,now(),'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
 (gen_random_uuid(),12,'00000000-0000-0000-0000-000000000001','user','user','active-question','[]',false,now(),'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
 (gen_random_uuid(),13,'00000000-0000-0000-0000-000000000001','assistant','user','active-partial-answer','[]',false,now(),'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'),
 (gen_random_uuid(),14,'00000000-0000-0000-0000-000000000001','assistant','notification','visible-notification','[]',true,now(),NULL),
 (gen_random_uuid(),15,'00000000-0000-0000-0000-000000000001','user','upload','visible-upload-caption','[]',true,now(),NULL),
 (gen_random_uuid(),16,'00000000-0000-0000-0000-000000000001','assistant','control','control-secret','[]',false,now(),NULL),
 (gen_random_uuid(),17,'00000000-0000-0000-0000-000000000001','assistant','context','context-secret','[]',false,now(),NULL);`)
	if err != nil {
		t.Fatal(err)
	}
	read := func(filter string, from, to int64, limit int, completed ...bool) []string {
		t.Helper()
		onlyCompleted := len(completed) > 0 && completed[0]
		rows, err := conn.Query(ctx, personHistorySQL, "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", from, to, nil, filter, limit, onlyCompleted)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []string
		for rows.Next() {
			var id, conv, run, role, content string
			var seq int64
			var created time.Time
			if err := rows.Scan(&id, &seq, &conv, &run, &role, &content, &created); err != nil {
				t.Fatal(err)
			}
			result = append(result, content)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return result
	}
	got := read("", 0, 9, 200)
	if len(got) != 3 || got[0] != "visible-reply" || got[1] != "text-2" || got[2] != "text-1" {
		t.Fatalf("history=%v", got)
	}
	if got := read("00000000-0000-0000-0000-000000000003", 0, 0, 200); len(got) != 0 {
		t.Fatalf("cross-user leak=%v", got)
	}
	if got := read("", 3, 5, 200); len(got) != 0 {
		t.Fatalf("cross-user/agent/source sequence leak=%v", got)
	}
	if got := read("", 0, 9, 1); len(got) != 1 || got[0] != "visible-reply" {
		t.Fatalf("latest tail=%v", got)
	}
	if got := read("", 0, 0, 200, true); len(got) != 2 || got[0] != "completed-answer" || got[1] != "completed-question" {
		t.Fatalf("completed pairing=%v", got)
	}
	if got := read("", 12, 13, 200); len(got) != 2 || got[0] != "active-partial-answer" || got[1] != "active-question" {
		t.Fatalf("read_past lost visible active history=%v", got)
	}
	if got := read("", 14, 0, 200); len(got) != 2 || got[0] != "visible-upload-caption" || got[1] != "visible-notification" {
		t.Fatalf("visible ephemeral history=%v", got)
	}
}
