package appruntime

import (
	"errors"
	"testing"

	"github.com/airlockrun/airlock/apperr"
	"github.com/google/uuid"
)

func TestParseCurrentConversationIDAcceptsOnlyCanonicalBoundConversation(t *testing.T) {
	want := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got, err := parseCurrentConversationID(want.String())
	if err != nil || got != want {
		t.Fatalf("valid conversation = %s, %v", got, err)
	}

	for _, raw := range []string{"", "not-a-uuid", uuid.Nil.String()} {
		t.Run(raw, func(t *testing.T) {
			if _, err := parseCurrentConversationID(raw); !errors.Is(err, apperr.ErrInvalidInput) {
				t.Fatalf("parseCurrentConversationID(%q) error = %v", raw, err)
			}
		})
	}
}
