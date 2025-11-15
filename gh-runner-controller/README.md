# GitHub Actions Runner Controller

A lightweight controller for autoscaling self-hosted GitHub Actions runners.

## Overview

This project provides automated scaling of GitHub Actions runners based on workflow queue depth. It supports multiple infrastructure providers and aims to reduce operational costs while maintaining availability.

## Features

- Automated scaling based on GitHub Actions queue metrics
- Support for multiple provider backends (Docker, AWS, GCP, Azure)
- REST API for monitoring and management
- Prometheus-compatible metrics endpoint
- Configurable scaling thresholds and policies
- Built-in analytics and decision tracking

## Requirements

- Go 1.21 or higher
- GitHub Personal Access Token with appropriate repository or organization permissions
- Docker (optional, required for Docker provider)

## Installation

### From Source

```bash
git clone https://github.com/yourusername/gh-runner-controller
cd gh-runner-controller
make build
./bin/controller
```

### Using Docker

```bash
cp .env.example .env
# Configure .env with your settings
docker-compose -f docker/docker-compose.yml up
```

## Configuration

Configuration is managed through environment variables:

**Required:**
- `GITHUB_TOKEN` - GitHub Personal Access Token
- `GITHUB_ORG` or `GITHUB_REPO` - Target organization or repository

**Optional:**
- `MIN_RUNNERS` - Minimum number of runners (default: 1)
- `MAX_RUNNERS` - Maximum number of runners (default: 10)
- `SCALE_UP_THRESHOLD` - Queue size to trigger scaling up (default: 5)
- `SCALE_DOWN_THRESHOLD` - Queue size to trigger scaling down (default: 0)
- `CHECK_INTERVAL_SEC` - Reconciliation interval in seconds (default: 30)
- `RUNNER_PROVIDER` - Provider type: docker, aws, gcp, azure (default: docker)

See `.env.example` for complete configuration options.

## Architecture

The controller operates on a reconciliation loop pattern:

1. Query GitHub API for queued workflow jobs
2. Compare queue depth against configured thresholds
3. Calculate desired runner count within min/max bounds
4. Issue scale up/down commands to provider
5. Record metrics and scaling decisions
6. Wait for configured interval and repeat

## API

The controller exposes a REST API for monitoring:

- `GET /health` - Health check endpoint
- `GET /api/v1/metrics` - Current metrics and runner status
- `GET /api/v1/runners` - List of managed runners
- `GET /api/v1/history` - Scaling decision history

See `docs/api.md` for detailed API documentation.

## Development

### Building

```bash
make build
```

### Testing

```bash
make test
make test-coverage
```

### Code Quality

```bash
make lint
make fmt
```

## Project Status

Current implementation includes:
- Core reconciliation loop
- GitHub API client
- Configuration management
- REST API endpoints
- Metrics collection
- Docker infrastructure

In development:
- Full Docker provider implementation
- AWS EC2 provider
- GCP Compute Engine provider
- Azure VM provider
- Webhook-based event handling
- Web-based dashboard

## Roadmap

**Phase 1 - Core Functionality**
- Complete Docker provider implementation
- Add comprehensive test coverage
- Implement basic observability

**Phase 2 - Cloud Providers**
- AWS EC2 provider with spot instance support
- GCP Compute Engine provider
- Azure VM provider

**Phase 3 - Advanced Features**
- Webhook-based scaling for faster response times
- Runner pool management with warm standby
- Cost tracking and optimization
- Multi-region deployment support

**Phase 4 - Enterprise Features**
- High availability with leader election
- Advanced scheduling algorithms
- Custom metrics and webhooks
- Web-based management dashboard

## Contributing

Contributions are welcome. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure all tests pass and code is formatted
5. Submit a pull request with clear description

### Code Standards

- Follow Go standard formatting (run `make fmt`)
- Maintain test coverage above 70%
- Add documentation for public APIs
- Use conventional commit messages

### Pull Request Process

1. Ensure CI pipeline passes
2. Update documentation if needed
3. Add entry to CHANGELOG if applicable
4. Request review from maintainers
5. Address review feedback

### Reporting Issues

When reporting bugs, include:
- Go version and operating system
- Controller configuration (sanitized)
- Relevant log output
- Steps to reproduce

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Documentation

- [Setup Guide](docs/setup.md)
- [API Reference](docs/api.md)
- [Contributing Guidelines](CONTRIBUTING.md)

## Contact

- Issues: https://github.com/yourusername/gh-runner-controller/issues
- Discussions: https://github.com/yourusername/gh-runner-controller/discussions
