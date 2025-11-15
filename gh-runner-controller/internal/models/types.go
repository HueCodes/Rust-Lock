package models

import "time"

// Runner represents a GitHub Actions runner instance
type Runner struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Status      string    `json:"status"` // idle, busy, offline
	Provider    string    `json:"provider"` // docker, aws, gcp, azure
	Labels      []string  `json:"labels"`
	StartedAt   time.Time `json:"started_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	WorkflowJob string    `json:"workflow_job,omitempty"`
}

// WorkflowJob represents a GitHub Actions workflow job
type WorkflowJob struct {
	ID          int64     `json:"id"`
	RunID       int64     `json:"run_id"`
	Status      string    `json:"status"` // queued, in_progress, completed
	Conclusion  string    `json:"conclusion,omitempty"`
	Name        string    `json:"name"`
	Labels      []string  `json:"labels"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// ScalingDecision represents a scaling action decision
type ScalingDecision struct {
	Action       string    `json:"action"` // scale_up, scale_down, none
	CurrentCount int       `json:"current_count"`
	DesiredCount int       `json:"desired_count"`
	QueuedJobs   int       `json:"queued_jobs"`
	Reason       string    `json:"reason"`
	Timestamp    time.Time `json:"timestamp"`
}

// Metrics represents controller metrics
type Metrics struct {
	ActiveRunners   int       `json:"active_runners"`
	IdleRunners     int       `json:"idle_runners"`
	QueuedJobs      int       `json:"queued_jobs"`
	RunningJobs     int       `json:"running_jobs"`
	LastReconcile   time.Time `json:"last_reconcile"`
	ReconcileErrors int       `json:"reconcile_errors"`
}

// ProviderConfig represents provider-specific configuration
type ProviderConfig struct {
	Type   string                 `json:"type"` // docker, aws, gcp, azure
	Config map[string]interface{} `json:"config"`
}
