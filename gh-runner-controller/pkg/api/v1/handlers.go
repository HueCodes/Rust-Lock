package v1

import (
	"encoding/json"
	"net/http"

	"gh-runner-controller/internal/analytics"
	"gh-runner-controller/internal/runner"
)

// Handler provides HTTP API endpoints
type Handler struct {
	runnerMgr *runner.Manager
	tracker   *analytics.Tracker
}

// NewHandler creates a new API handler
func NewHandler(rm *runner.Manager, tracker *analytics.Tracker) *Handler {
	return &Handler{
		runnerMgr: rm,
		tracker:   tracker,
	}
}

// HandleHealth returns service health status
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// HandleMetrics returns current metrics
func (h *Handler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := h.tracker.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// HandleRunners returns list of runners
func (h *Handler) HandleRunners(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement once runner listing is available
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   h.runnerMgr.Count(),
		"runners": []interface{}{},
	})
}

// HandleHistory returns scaling decision history
func (h *Handler) HandleHistory(w http.ResponseWriter, r *http.Request) {
	history := h.tracker.GetHistory(50)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}
