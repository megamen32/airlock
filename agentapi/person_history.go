package agentapi

import (
	"github.com/airlockrun/airlock/service/appruntime"
	"net/http"
)

func (h *Handler) SessionLoadPerson(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(r.Header.Get("X-Airlock-Run-ID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	var query appruntime.PersonHistoryQuery
	if err := readAppJSON(r, &query); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.appService().SessionLoadPerson(callbackContext(r), runID, query)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
