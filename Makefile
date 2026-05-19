BINARY   := vault
MODULE   := github.com/zafrem/bastion-vault
GO       := go
GOFLAGS  := -trimpath -ldflags="-s -w"
BUILD_DIR := ./bin

.PHONY: all build test lint vet fmt tidy clean docker-build docker-up docker-down help

all: tidy fmt vet build

## build: Compile the vault binary
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/vault

## run-server: Build and start the server (requires VAULT_KMS_LOCAL_MASTER_KEY)
run-server: build
	$(BUILD_DIR)/$(BINARY) server

## test: Run all unit tests with race detector
test:
	$(GO) test -race -count=1 ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GO) test -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

## lint: Run golangci-lint (requires golangci-lint to be installed)
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## fmt: Format source files
fmt:
	$(GO) fmt ./...

## tidy: Tidy go.mod / go.sum
tidy:
	$(GO) mod tidy

## clean: Remove build artifacts
clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

## docker-build: Build the Docker image
docker-build:
	docker build -f deployments/Dockerfile -t bastion-vault:dev .

## docker-up: Start the full dev stack with Docker Compose
docker-up:
	docker compose -f deployments/docker-compose.yml up -d

## docker-down: Stop the dev stack
docker-down:
	docker compose -f deployments/docker-compose.yml down -v

## gen-master-key: Generate a random 32-byte hex master key
gen-master-key:
	@openssl rand -hex 32

## detect-pii: Run PII detection on customer samples
detect-pii: build
	$(BUILD_DIR)/$(BINARY) detect-pii -i tests/fixtures/customer_data_samples.jsonl

## classify: Classify customer samples
classify: build
	$(BUILD_DIR)/$(BINARY) classify -i tests/fixtures/customer_data_samples.jsonl

## k-anon: Validate k-anonymity on customer samples
k-anon: build
	$(BUILD_DIR)/$(BINARY) k-anon-check \
		-i tests/fixtures/customer_data_samples.jsonl \
		-t DC-01 -k 5

## help: Display this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
