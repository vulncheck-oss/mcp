FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder
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

FROM gcr.io/distroless/static-debian12@sha256:a9fcaedd4c9b59e12dd65d954f0b5044f19b0647a8a3712e77205df9e7b102cd
LABEL io.modelcontextprotocol.server.name="io.github.vulncheck-oss/mcp"
COPY --from=builder /vulncheck-mcp /vulncheck-mcp
ENTRYPOINT ["/vulncheck-mcp"]
CMD ["-transport", "stdio"]