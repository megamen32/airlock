package runtime

import (
	"strings"
	"testing"

	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/testutil"
)

func TestExtractInlineReasoningHidesThinkTags(t *testing.T) {
	model := testutil.NewMockLanguageModel(testutil.MockLanguageModelOptions{
		StreamResponse: testutil.MockTextResponse("<think>private chain</think>VISIBLE", testutil.MockUsage(1, 1)),
	})
	events, err := extractInlineReasoning(model, true).Stream(t.Context(), &stream.CallOptions{})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}

	var visible, reasoning strings.Builder
	for event := range events {
		switch data := event.Data.(type) {
		case stream.TextDeltaEvent:
			visible.WriteString(data.Text)
		case stream.ReasoningDeltaEvent:
			reasoning.WriteString(data.Text)
		}
	}
	if got := visible.String(); got != "VISIBLE" {
		t.Errorf("visible text = %q, want %q", got, "VISIBLE")
	}
	if got := reasoning.String(); got != "private chain" {
		t.Errorf("reasoning text = %q, want %q", got, "private chain")
	}
}
