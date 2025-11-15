# API Documentation

## Endpoints

### Health Check

Check if the controller is running.

```
GET /health
```

**Response:**
```json
{
  "status": "healthy"
}
```

---

### Metrics

Get current controller metrics.

```
GET /api/v1/metrics
```

**Response:**
```json
{
  "active_runners": 5,
  "idle_runners": 2,
  "queued_jobs": 3,
  "running_jobs": 3,
  "last_reconcile": "2024-11-14T18:00:00Z",
  "reconcile_errors": 0
}
```

---

### Runners

List all managed runners.

```
GET /api/v1/runners
```

**Response:**
```json
{
  "count": 5,
  "runners": [
    {
      "id": "runner-123",
      "name": "runner-123",
      "status": "idle",
      "provider": "docker",
      "labels": ["self-hosted", "linux"],
      "started_at": "2024-11-14T17:00:00Z",
      "last_seen_at": "2024-11-14T18:00:00Z"
    }
  ]
}
```

---

### History

Get scaling decision history.

```
GET /api/v1/history?limit=50
```

**Response:**
```json
[
  {
    "action": "scale_up",
    "current_count": 3,
    "desired_count": 5,
    "queued_jobs": 8,
    "reason": "Queue threshold exceeded",
    "timestamp": "2024-11-14T18:00:00Z"
  }
]
```

---

## Webhooks (Future)

### GitHub Webhook

Receive workflow job events from GitHub.

```
POST /api/v1/webhook/github
```

**Headers:**
- `X-GitHub-Event: workflow_job`
- `X-Hub-Signature-256: sha256=...`

**Payload:**
```json
{
  "action": "queued",
  "workflow_job": {
    "id": 123,
    "run_id": 456,
    "status": "queued",
    "labels": ["self-hosted", "linux"]
  }
}
```
