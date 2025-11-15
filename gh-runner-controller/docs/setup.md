# Setup Guide

## Prerequisites

- Go 1.21 or higher
- Docker (optional, for Docker provider)
- GitHub Personal Access Token with appropriate permissions

## Installation

### From Source

```bash
git clone https://github.com/yourusername/gh-runner-controller
cd gh-runner-controller
make build
```

### Using Docker

```bash
docker-compose -f docker/docker-compose.yml up
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:

- `GITHUB_TOKEN` - GitHub PAT with `repo` and `admin:org` scopes
- `GITHUB_ORG` or `GITHUB_REPO` - Target organization or repository

Optional variables:

- `MIN_RUNNERS` (default: 1) - Minimum number of runners
- `MAX_RUNNERS` (default: 10) - Maximum number of runners
- `SCALE_UP_THRESHOLD` (default: 5) - Jobs threshold to scale up
- `SCALE_DOWN_THRESHOLD` (default: 0) - Jobs threshold to scale down
- `CHECK_INTERVAL_SEC` (default: 30) - Reconciliation interval

### GitHub Token Permissions

Your GitHub token needs the following permissions:

**For Organization:**
- `admin:org` - Manage organization runners

**For Repository:**
- `repo` - Full repository access
- `admin:repo_hook` - Manage webhooks (for webhook mode)

### Creating a GitHub Token

1. Go to GitHub Settings → Developer Settings → Personal Access Tokens
2. Generate new token (classic)
3. Select required scopes
4. Copy and save the token

## Running

### Development Mode

```bash
export GITHUB_TOKEN=ghp_your_token_here
export GITHUB_ORG=your-org
make run
```

### Production Mode

```bash
./bin/controller
```

### With Docker

```bash
docker-compose up -d
```

## Providers

### Docker Provider

The Docker provider spawns runners as Docker containers.

**Requirements:**
- Docker installed and running
- Docker socket accessible

**Configuration:**
```env
RUNNER_PROVIDER=docker
DOCKER_IMAGE=myoung34/github-runner:latest
```

### AWS Provider (Coming Soon)

Spawn runners as EC2 instances.

### GCP Provider (Coming Soon)

Spawn runners as GCE instances.

### Azure Provider (Coming Soon)

Spawn runners as Azure VMs.

## Monitoring

### Metrics Endpoint

Prometheus metrics available at:
```
http://localhost:9090/metrics
```

### Dashboard

Grafana dashboard available at:
```
http://localhost:3000
```

Default credentials: `admin` / `admin`

## Troubleshooting

### Controller not starting

Check that:
- `GITHUB_TOKEN` is set and valid
- `GITHUB_ORG` or `GITHUB_REPO` is configured
- Token has required permissions

### Runners not scaling

Check:
- Queue depth is above/below thresholds
- Min/max runner limits
- Provider configuration is correct
- Docker socket is accessible (for Docker provider)

### GitHub API rate limiting

If you hit rate limits:
- Increase `CHECK_INTERVAL_SEC`
- Use webhook mode instead of polling (coming soon)
- Use multiple tokens (enterprise feature)

## Next Steps

- [API Documentation](api.md)
- [Contributing Guide](contrib.md)
- [Architecture Overview](../README.md#architecture)
