package api

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/convert"
)

// DownloadConversationFile streams only a file already delivered to a
// conversation owned by the caller. It does not grant storage browsing access.
func (h *conversationsHandler) DownloadConversationFile(w http.ResponseWriter, r *http.Request) {
	conv, ok := h.ownedConversation(r.Context(), w, r)
	if !ok {
		return
	}
	source := r.URL.Query().Get("source")
	if source == "" || len(source) > 2048 || h.s3 == nil {
		writeError(w, http.StatusBadRequest, "invalid file source")
		return
	}
	var raw []byte
	err := h.db.Pool().QueryRow(r.Context(), `SELECT parts FROM agent_messages
WHERE conversation_id=$1 AND role='assistant' AND source IN ('user','notification')
AND EXISTS (SELECT 1 FROM jsonb_array_elements(parts) AS p WHERE p->>'type'='file' AND p->>'source'=$2)
LIMIT 1`, conv.ID, source).Scan(&raw)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	part, ok := deliveredFile(raw, source, convert.PgUUIDToString(conv.AgentID))
	if !ok {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	body, err := h.s3.GetObject(r.Context(), source)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	defer body.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": part.Filename}))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, body)
}

func deliveredFile(raw []byte, source, agentID string) (wire.DisplayPart, bool) {
	if !strings.HasPrefix(source, "agents/"+agentID+"/media/") || path.Clean(source) != source {
		return wire.DisplayPart{}, false
	}
	var parts []wire.DisplayPart
	if json.Unmarshal(raw, &parts) != nil {
		return wire.DisplayPart{}, false
	}
	for _, part := range parts {
		if part.Type != "file" || part.Source != source {
			continue
		}
		if part.Filename == "" {
			part.Filename = path.Base(source)
		}
		if part.Filename == "." || part.Filename == ".." || strings.ContainsAny(part.Filename, "/\\\r\n\x00") {
			return wire.DisplayPart{}, false
		}
		return part, true
	}
	return wire.DisplayPart{}, false
}
