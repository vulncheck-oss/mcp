FROM golang:1.26-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS builder
ARG VERSION=dev
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /vulncheck-mcp ./cmd/vulncheck-mcp

FROM gcr.io/distroless/static-debian12@sha256:9c346e4be81b5ca7ff31a0d89eaeade58b0f95cfd3baed1f36083ddb47ca3160
LABEL io.modelcontextprotocol.server.name="io.github.vulncheck-oss/mcp"
COPY --from=builder /vulncheck-mcp /vulncheck-mcp
ENTRYPOINT ["/vulncheck-mcp"]
CMD ["-transport", "stdio"]