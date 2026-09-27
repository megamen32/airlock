package runtime

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/testutil"
	solprovider "github.com/airlockrun/sol/provider"
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

// The production MiniMax route is an OpenAI-compatible provider. Its catalog
// Reasoning flag enables extraction, not a provider reasoning-effort parameter.
// Exercise the real SSE adapter: parsing after the stream would already have
// leaked the private text to Sol history and bridge text-delta delivery.
func TestMiniMaxCompatibleStreamSeparatesInlineReasoningBeforeConsumers(t *testing.T) {
	for _, tc := range []struct {
		name               string
		chunks             []string
		visible, reasoning string
	}{
		{"split markers", []string{"<thi", "nk>private ", "analysis</th", "ink>Visible answer"}, "Visible answer", "private analysis"},
		{"unclosed reasoning", []string{"<think>", "private unfinished analysis"}, "", "private unfinished analysis"},
		{"empty reasoning", []string{"<think>", "</think>", "Visible answer"}, "Visible answer", ""},
		{"plain answer", []string{"Visible ", "answer"}, "Visible answer", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/chat/completions" {
					t.Errorf("unexpected provider path %s", r.URL.Path)
				}
				var request map[string]any
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if request["model"] != "minimax/MiniMax-M3" || request["stream"] != true {
					t.Error("wrong model or non-streaming request")
				}
				if _, ok := request["reasoning_effort"]; ok {
					t.Error("extraction unexpectedly changed provider reasoning settings")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				emit := func(delta map[string]any, finish any) {
					payload, _ := json.Marshal(map[string]any{"id": "test-stream", "object": "chat.completion.chunk", "model": "minimax/MiniMax-M3", "choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}})
					fmt.Fprintf(w, "data: %s\n\n", payload)
				}
				for _, chunk := range tc.chunks {
					emit(map[string]any{"content": chunk}, nil)
				}
				emit(map[string]any{"tool_calls": []any{map[string]any{"index": 0, "id": "call-proof", "type": "function", "function": map[string]any{"name": "read_past", "arguments": `{"query":"facts"}`}}}}, nil)
				emit(map[string]any{}, "tool_calls")
				fmt.Fprint(w, "data: [DONE]\n\n")
			}))
			defer server.Close()
			base := solprovider.CreateModel("openai-compatible", "minimax/MiniMax-M3", solprovider.Options{BaseURL: server.URL, APIKey: "test", HTTPClient: server.Client()})
			events, err := extractInlineReasoning(base, true).Stream(t.Context(), &stream.CallOptions{})
			if err != nil {
				t.Fatal(err)
			}
			var visible, reasoning strings.Builder
			toolCalls := 0
			for ev := range events {
				switch data := ev.Data.(type) {
				case stream.TextDeltaEvent:
					visible.WriteString(data.Text)
					if strings.Contains(data.Text, "private") || strings.Contains(data.Text, "<think>") {
						t.Error("private text crossed visible streaming boundary")
					}
				case stream.ReasoningDeltaEvent:
					reasoning.WriteString(data.Text)
				case stream.ToolCallEvent:
					toolCalls++
					if data.ToolCallID != "call-proof" || data.ToolName != "read_past" || string(data.Input) != `{"query":"facts"}` {
						t.Errorf("tool payload changed: %+v", data)
					}
				case stream.ErrorEvent:
					t.Errorf("provider stream failed: %v", data.Error)
				}
			}
			if visible.String() != tc.visible || reasoning.String() != tc.reasoning || toolCalls != 1 {
				t.Fatalf("visible=%q reasoning=%q tools=%d", visible.String(), reasoning.String(), toolCalls)
			}
		})
	}
}
