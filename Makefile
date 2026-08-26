.PHONY: build run test clean config

# Build the binary
build:
	go build -o hustler ./cmd/hustler

# Run the server
run: build
	./hustler serve

# Run with custom config
run-config: build
	HUSTLER_CONFIG=/path/to/config.json ./hustler serve

# Install dependencies
deps:
	go mod tidy
	go mod download

# Clean build artifacts
clean:
	rm -f hustler
	rm -rf ~/.hustler

# Create default config
config:
	mkdir -p ~/.hustler
	cp configs/config.json ~/.hustler/config.json

# Test build
test: build
	./hustler --help
	./hustler target --help
	./hustler job --help

# Run with race detector
race:
	go build -race -o hustler-race ./cmd/hustler

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Lint
lint:
	golangci-lint run ./...

# Generate mocks (if using mockery)
mocks:
	mockery --all --output internal/mocks

# Docker build
docker-build:
	docker build -t hustler .

# Docker run
docker-run:
	docker run -p 8081:8081 -p 88:88 hustler

# All checks
check: fmt vet test

# Development setup
dev-setup: deps config build

# Default target
all: build