package agentapi

import (
	"encoding/json"
	"testing"
)

func TestNativeMCPDiscoverySchemasAreObjectsNotBase64(t *testing.T) {
	tool := nativeMCPTool("remember", "", []byte(`{"type":"object","properties":{"text":{"type":"string"}}}`), []byte(`{"type":"object"}`))
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"inputSchema", "outputSchema"} {
		schema, ok := data[key].(map[string]any)
		if !ok || schema["type"] != "object" {
			t.Fatalf("MCP schema must be JSON object: %s", raw)
		}
	}
}
