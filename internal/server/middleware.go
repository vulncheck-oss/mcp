package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxRequestBodyBytes = 128 * 1024

func NewLogger() *slog.Logger {
	return slog.New(
		slog.NewJSONHandler(
			os.Stderr,
			&slog.HandlerOptions{Level: slog.LevelInfo},
		),
	)
}

// tokenMapKey returns the full SHA-256 hex of the token for use as a map key.
func tokenMapKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

// tokenLogID returns the first 8 bytes (16 hex chars) of the SHA-256 for log annotation.
func tokenLogID(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h[:8])
}

// mcpToolName extracts the tool name from a tools/call JSON-RPC request body.
// Returns "" if the body is not a tools/call request or parsing fails.
func mcpToolName(body []byte) string {
	var rpc struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &rpc) != nil || rpc.Method != "tools/call" {
		return ""
	}
	return rpc.Params.Name
}

// responseCapture wraps http.ResponseWriter to capture the status code and
// response body so the middleware can detect MCP-level tool errors (isError:true).
type responseCapture struct {
	http.ResponseWriter
	code int
	body bytes.Buffer
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.code = code
	rc.ResponseWriter.WriteHeader(code)
}

func (rc *responseCapture) Write(b []byte) (int, error) {
	rc.body.Write(b)
	return rc.ResponseWriter.Write(b)
}

func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Auth401 returns 401 when the Authorization header is absent or carries an empty Bearer token,
// giving clients an explicit HTTP response instead of the implicit nil-server behavior in the MCP SDK.
func Auth401(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vulncheck-mcp"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NewAuditMiddleware returns an HTTP middleware that logs every MCP tool call with a
// structured JSON log line: request ID, token identity (SHA-256 prefix), tool name,
// HTTP status, and latency. It also enforces a maximum request body size.
func NewAuditMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		logID := tokenLogID(token)

		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = fmt.Sprintf("%d-%s", start.UnixNano(), logID[:4])
		}

		var toolName string
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				logger.LogAttrs(r.Context(), slog.LevelWarn, "request_too_large",
					slog.String("request_id", reqID),
					slog.String("token_id", logID),
				)
				http.Error(w, "Request Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			toolName = mcpToolName(body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		rw := &responseCapture{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rw, r)

		toolError := bytes.Contains(rw.body.Bytes(), []byte(`"isError":true`))
		logHTTPRequests(toolName, toolError, logger, r, reqID, logID, rw, start)
	})
}

func logHTTPRequests(toolName string, toolError bool, logger *slog.Logger, r *http.Request, reqID string, logID string, rw *responseCapture, start time.Time) {
	logAttrs := []slog.Attr{
		slog.String("request_id", reqID),
		slog.String("token_id", logID),
		slog.Int("status", rw.code),
		slog.Int64("latency_ms", time.Since(start).Milliseconds()),
	}

	if toolName != "" {
		level := slog.LevelInfo
		if toolError {
			level = slog.LevelWarn
		}

		logger.LogAttrs(r.Context(), level, "tool_call",
			append(logAttrs, slog.String("tool", toolName), slog.Bool("tool_error", toolError))...,
		)
		return
	}

	logger.LogAttrs(r.Context(), slog.LevelDebug, "mcp_request", logAttrs...)
}
