package analytics

import (
	"sync"
	"time"

	"gh-runner-controller/internal/models"
)

// Tracker tracks runner and job metrics
type Tracker struct {
	mu      sync.RWMutex
	metrics models.Metrics
	history []models.ScalingDecision
}

// NewTracker creates a new analytics tracker
func NewTracker() *Tracker {
	return &Tracker{
		history: make([]models.ScalingDecision, 0, 100),
	}
}

// UpdateMetrics updates the current metrics
func (t *Tracker) UpdateMetrics(m models.Metrics) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.metrics = m
}

// RecordDecision records a scaling decision
func (t *Tracker) RecordDecision(decision models.ScalingDecision) {
	t.mu.Lock()
	defer t.mu.Unlock()

	decision.Timestamp = time.Now()
	t.history = append(t.history, decision)

	// Keep only last 100 decisions
	if len(t.history) > 100 {
		t.history = t.history[1:]
	}
}

// GetMetrics returns current metrics
func (t *Tracker) GetMetrics() models.Metrics {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.metrics
}

// GetHistory returns scaling decision history
func (t *Tracker) GetHistory(limit int) []models.ScalingDecision {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit <= 0 || limit > len(t.history) {
		limit = len(t.history)
	}

	start := len(t.history) - limit
	result := make([]models.ScalingDecision, limit)
	copy(result, t.history[start:])
	return result
}
