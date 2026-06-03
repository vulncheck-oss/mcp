// Command vulncheck-mcp is an MCP server exposing VulnCheck vulnerability and exploit intelligence.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/vulncheck-oss/mcp/internal/client"
	"github.com/vulncheck-oss/mcp/internal/server"
)

var version = "dev"

func main() {
	transport := flag.String("transport", "stdio", "Transport type: stdio or http")
	port := flag.String("port", ":8080", "HTTP listen address (only used with -transport http)")
	flag.Parse()

	tok := os.Getenv("VULNCHECK_API_TOKEN")
	if tok == "" && *transport == "stdio" {
		fmt.Fprintln(os.Stderr, "error: VULNCHECK_API_TOKEN environment variable not set")
		os.Exit(1)
	}

	switch *transport {
	case "stdio":
		if err := runStdio(tok); err != nil {
			log.Fatal(err)
		}
	case "http":
		if err := runHTTP(*port); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown transport %q, must be stdio or http\n", *transport)
		os.Exit(1)
	}
}

func runStdio(token string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return server.New(client.New(token, version), version, nil).Run(ctx, &mcp.StdioTransport{})
}

func runHTTP(addr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cache := mcp.NewSchemaCache()
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if tok == "" {
				return nil
			}
			return server.New(client.New(tok, version), version, cache)
		},
		&mcp.StreamableHTTPOptions{Stateless: true},
	)

	logger := server.NewLogger()

	mux := http.NewServeMux()
	mux.Handle("/mcp", server.NewAuditMiddleware(logger, server.Auth401(mcpHandler)))
	mux.Handle("/mcp/", server.NewAuditMiddleware(logger, server.Auth401(mcpHandler)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, version)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("vulncheck MCP server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
