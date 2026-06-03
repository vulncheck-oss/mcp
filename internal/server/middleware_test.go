package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenLogID(t *testing.T) {
	a := tokenLogID("token-a")
	b := tokenLogID("token-b")
	assert.Len(t, a, 16)
	assert.Len(t, b, 16)
	assert.NotEqual(t, a, b)
	assert.Equal(t, a, tokenLogID("token-a"), "must be deterministic")
}

func TestTokenMapKey(t *testing.T) {
	a := tokenMapKey("token-a")
	b := tokenMapKey("token-b")
	assert.Len(t, a, 64)
	assert.NotEqual(t, a, b)
	assert.Equal(t, a, tokenMapKey("token-a"), "must be deterministic")
}

func TestMCPToolName(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "tools/call with name",
			body:     `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search_index"},"id":1}`,
			expected: "search_index",
		},
		{
			name:     "initialize method",
			body:     `{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}`,
			expected: "",
		},
		{
			name:     "malformed JSON",
			body:     `not json`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     ``,
			expected: "",
		},
		{
			name:     "tools/call missing name",
			body:     `{"jsonrpc":"2.0","method":"tools/call","params":{},"id":1}`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mcpToolName([]byte(tt.body)))
		})
	}
}

func TestAuth401(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Auth401(inner)

	t.Run("missing Authorization header", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, `Bearer realm="vulncheck-mcp"`, rr.Header().Get("WWW-Authenticate"))
	})

	t.Run("empty Bearer token", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer ")
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Equal(t, `Bearer realm="vulncheck-mcp"`, rr.Header().Get("WWW-Authenticate"))
	})

	t.Run("valid Bearer token passes through", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer mytoken")
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}

func TestAuditMiddleware_LogsToolCall(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	})
	handler := NewAuditMiddleware(logger, inner)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_indices"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer testtoken")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	log := buf.String()
	assert.Contains(t, log, "tool_call")
	assert.Contains(t, log, "list_indices")
	assert.Contains(t, log, "token_id")
	assert.Contains(t, log, "request_id")
	assert.Contains(t, log, "latency_ms")
	assert.Contains(t, log, `"tool_error":false`)
}

func TestAuditMiddleware_LogsToolError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"401 Unauthorized"}],"isError":true}}`))
	})
	handler := NewAuditMiddleware(logger, inner)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_backup"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer badtoken")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	log := buf.String()
	assert.Contains(t, log, `"tool_error":true`)
	assert.Contains(t, log, "WARN")
}

func TestAuditMiddleware_RequestTooLarge(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := NewAuditMiddleware(logger, inner)

	oversized := strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1))
	req := httptest.NewRequest(http.MethodPost, "/mcp", oversized)
	req.Header.Set("Authorization", "Bearer testtoken")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, rr.Code)
	assert.Contains(t, buf.String(), "request_too_large")
}

func TestAuditMiddleware_XRequestIDPassthrough(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := NewAuditMiddleware(logger, inner)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_indices"},"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer testtoken")
	req.Header.Set("X-Request-ID", "my-trace-id")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Contains(t, buf.String(), "my-trace-id")
}
