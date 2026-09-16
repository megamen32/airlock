package agentapi

import "net/http"

func (h *Handler) AddMember(w http.ResponseWriter, r *http.Request)    { h.mutateMember(w, r, false) }
func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) { h.mutateMember(w, r, true) }

func (h *Handler) mutateMember(w http.ResponseWriter, r *http.Request, remove bool) {
	runID, err := parseUUID(r.Header.Get("X-Airlock-Run-ID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	var req struct {
		UserID string `json:"userId"`
	}
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.appService().MutateMember(callbackContext(r), runID, req.UserID, remove); err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
