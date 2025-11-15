package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

const baseURL = "http://localhost:8080"

type Metrics struct {
	ActiveRunners   int    `json:"active_runners"`
	IdleRunners     int    `json:"idle_runners"`
	QueuedJobs      int    `json:"queued_jobs"`
	RunningJobs     int    `json:"running_jobs"`
	ReconcileErrors int    `json:"reconcile_errors"`
}

func main() {
	// Check health
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Controller unhealthy: %d\n", resp.StatusCode)
		os.Exit(1)
	}

	fmt.Println("✓ Controller is healthy")

	// Get metrics
	resp, err = http.Get(baseURL + "/api/v1/metrics")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting metrics: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var metrics Metrics
	if err := json.Unmarshal(body, &metrics); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metrics: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nMetrics:\n")
	fmt.Printf("  Active Runners: %d\n", metrics.ActiveRunners)
	fmt.Printf("  Idle Runners:   %d\n", metrics.IdleRunners)
	fmt.Printf("  Queued Jobs:    %d\n", metrics.QueuedJobs)
	fmt.Printf("  Running Jobs:   %d\n", metrics.RunningJobs)
	fmt.Printf("  Errors:         %d\n", metrics.ReconcileErrors)
}
