# Contributing

## Requirements

- Go 1.21+
- Tests pass: `make test`
- Code formatted: `make lint`

## Process

1. Fork and clone
2. Create feature branch
3. Make changes with tests
4. Run `make test && make lint`
5. Open PR with clear description

## Standards

- Zero external dependencies unless required
- Tests for new features
- Minimal comments
- Functions under 50 lines

## Priority Areas

- Docker/containerd runner implementation
- VM providers (AWS, GCP, Azure)
- Webhook-based scaling
- Prometheus metrics
- Runner label matching
