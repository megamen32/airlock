package agentapi

import (
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
)

// agentMember is a principal granted access to the authenticated agent. A
// member can be either a user or the built-in all-users group; Kind lets
// agents send user-targeted notifications without mistaking a group ID for a
// user ID.
type agentMember struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Role string `json:"role"`
}

type listMembersResponse struct {
	Members []agentMember `json:"members"`
}

// Keep the flat roster fields consumed by already-deployed pre-0.7 agents
// alongside the upstream user/access representation and pagination.
func compatibleMembers(result wire.ListMembersResponse) any {
	type member struct {
		wire.Member
		ID   string `json:"id"`
		Kind string `json:"kind"`
		Role string `json:"role"`
	}
	members := make([]member, len(result.Members))
	for i, item := range result.Members {
		members[i] = member{Member: item, ID: item.User.ID, Kind: "user", Role: string(item.Access)}
	}
	return struct {
		Members    []member `json:"members"`
		NextCursor string   `json:"nextCursor,omitempty"`
	}{members, result.NextCursor}
}

func agentMembers(rows []dbq.ListAgentGrantsRow) []agentMember {
	members := make([]agentMember, len(rows))
	for i, row := range rows {
		members[i] = agentMember{
			ID:   row.GranteeID.String(),
			Kind: row.Kind,
			Role: row.Role,
		}
	}
	return members
}
