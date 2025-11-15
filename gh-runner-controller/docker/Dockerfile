# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o controller cmd/controller/main.go

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates docker-cli

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/controller .

# Create config directory
RUN mkdir -p /etc/gh-runner-controller

EXPOSE 8080 9090

CMD ["./controller"]
