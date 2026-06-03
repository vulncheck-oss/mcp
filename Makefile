.PHONY: build snapshot test coverage lint fmt docker-build clean serve

BINARY  := vulncheck-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/vulncheck-mcp

snapshot:
	goreleaser build --snapshot --clean

test:
	go test -race ./...

coverage:
	go test -race -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

fmt:
	gofmt -w .

lint:
	golangci-lint run

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

serve:
	go run -ldflags "$(LDFLAGS)" ./cmd/vulncheck-mcp -transport http -port $${PORT:-:8080}

clean:
	rm -rf bin/ dist/


