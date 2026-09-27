package agentapi

import (
	"encoding/json"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestMembersCompatibilityPreservesOldAndNewSDKResponses(t *testing.T) {
	input := wire.ListMembersResponse{Members: []wire.Member{{User: wire.MemberUser{ID: "user-id", DisplayName: "Member"}, Access: wire.Access("admin")}}, NextCursor: "cursor"}
	data, err := json.Marshal(compatibleMembers(input))
	if err != nil {
		t.Fatal(err)
	}
	var current wire.ListMembersResponse
	if err := json.Unmarshal(data, &current); err != nil {
		t.Fatal(err)
	}
	if current.NextCursor != input.NextCursor || current.Members[0].User.ID != "user-id" {
		t.Fatalf("lost current fields: %s", data)
	}
	var legacy listMembersResponse
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Members[0] != (agentMember{ID: "user-id", Kind: "user", Role: "admin"}) {
		t.Fatalf("lost legacy fields: %s", data)
	}
}

func TestAgentMembersReturnsOnlySafeRosterFields(t *testing.T) {
	userID := uuid.MustParse("4d9c4eb3-5661-4a8f-bcde-ea6f47988ea6")
	groupID := uuid.MustParse("afbf6e02-b244-4eef-b621-213ed70d8de5")
	members := agentMembers([]dbq.ListAgentGrantsRow{
		{GranteeID: pgtype.UUID{Bytes: userID, Valid: true}, Kind: "user", Role: "admin", Email: "private@example.test", DisplayName: "Private"},
		{GranteeID: pgtype.UUID{Bytes: groupID, Valid: true}, Kind: "group", Role: "public"},
	})

	if len(members) != 2 {
		t.Fatalf("len(members) = %d, want 2", len(members))
	}
	if got, want := members[0], (agentMember{ID: userID.String(), Kind: "user", Role: "admin"}); got != want {
		t.Fatalf("members[0] = %#v, want %#v", got, want)
	}
	if got, want := members[1], (agentMember{ID: groupID.String(), Kind: "group", Role: "public"}); got != want {
		t.Fatalf("members[1] = %#v, want %#v", got, want)
	}
}
