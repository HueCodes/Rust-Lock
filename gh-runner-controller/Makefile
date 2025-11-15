.PHONY: help build run test lint clean docker-build docker-run install deps coverage fmt vet ci

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building..."
	@go build -o bin/controller cmd/controller/main.go

run: ## Run the application
	@go run cmd/controller/main.go

test: ## Run tests
	@go test -v -race ./...

test-coverage: ## Run tests with coverage
	@go test -v -race -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

lint: fmt vet ## Run linter
	@golangci-lint run || echo "Install golangci-lint: https://golangci-lint.run/usage/install/"

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...

clean: ## Clean build artifacts
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@echo "Cleaned build artifacts"

deps: ## Download and tidy dependencies
	@go mod download
	@go mod tidy

install: build ## Install binary to GOPATH/bin
	@go install cmd/controller/main.go

docker-build: ## Build Docker image
	@docker build -f docker/Dockerfile -t gh-runner-controller:latest .

docker-run: ## Run with Docker Compose
	@docker-compose -f docker/docker-compose.yml up

docker-down: ## Stop Docker Compose
	@docker-compose -f docker/docker-compose.yml down

dev: ## Run in development mode with hot reload
	@which air > /dev/null || go install github.com/cosmtrek/air@latest
	@air

ci: deps lint test build ## Run CI pipeline locally
