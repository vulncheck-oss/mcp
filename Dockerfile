FROM golang:1.26-alpine@sha256:9097beb5536220f7857bdcb65c1b4b340630dd7a70b85f03d5af29640b06693d AS builder
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

FROM gcr.io/distroless/static-debian12@sha256:61b7ccecebc7c474a531717de80a94709d20547cdcdaf740c25876f2a8e38b44
LABEL io.modelcontextprotocol.server.name="io.github.vulncheck-oss/mcp"
COPY --from=builder /vulncheck-mcp /vulncheck-mcp
ENTRYPOINT ["/vulncheck-mcp"]
CMD ["-transport", "stdio"]