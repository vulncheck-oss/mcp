FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder
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

FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
LABEL io.modelcontextprotocol.server.name="io.github.vulncheck-oss/mcp"
COPY --from=builder /vulncheck-mcp /vulncheck-mcp
ENTRYPOINT ["/vulncheck-mcp"]
CMD ["-transport", "stdio"]