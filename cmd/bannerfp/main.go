// bannerfp contains the server, batch client, and container health probe.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gaojingjie11/bannerfp/internal/api"
	"github.com/gaojingjie11/bannerfp/internal/fingerprint"
)

const (
	defaultAddress = ":8080"
	defaultServer  = "http://server:8080"
	defaultRules   = "/config/rules.json"

	maxClientResponse = 16 << 20
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "serve":
		return runServer(args[1:])
	case "client":
		return runClient(args[1:], output)
	case "healthcheck":
		return runHealthcheck(args[1:])
	case "help", "-h", "--help":
		if _, err := fmt.Fprint(output, usage()); err != nil {
			return fmt.Errorf("write usage: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage())
	}
}

func runServer(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	address := flags.String("addr", envOrDefault("BANNERFP_ADDR", defaultAddress), "HTTP listen address")
	rulesPath := flags.String("rules", envOrDefault("BANNERFP_RULES", defaultRules), "fingerprint rules JSON file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("serve: unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	engine, err := fingerprint.LoadFile(*rulesPath)
	if err != nil {
		return fmt.Errorf("load fingerprint rules: %w", err)
	}

	server := &http.Server{
		Addr:              *address,
		Handler:           api.NewHandler(engine),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listenResult := make(chan error, 1)
	go func() {
		slog.Info("server listening", "address", *address)
		listenResult <- server.ListenAndServe()
	}()

	select {
	case err := <-listenResult:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		slog.Info("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	err = <-listenResult
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", err)
	}
	return nil
}

func runClient(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	serverURL := flags.String("server", envOrDefault("BANNERFP_SERVER", defaultServer), "server base URL")
	inputPath := flags.String("input", "", "input JSON file")
	timeout := flags.Duration("timeout", 30*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("client: unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *inputPath == "" {
		return errors.New("client: --input is required")
	}
	if *timeout <= 0 {
		return errors.New("client: --timeout must be positive")
	}

	input, err := os.ReadFile(*inputPath)
	if err != nil {
		return fmt.Errorf("read input file: %w", err)
	}
	if !json.Valid(input) {
		return errors.New("input file is not valid JSON")
	}

	endpoint := strings.TrimRight(*serverURL, "/") + "/fingerprint"
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(input))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: *timeout}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request fingerprint server: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxClientResponse+1))
	if err != nil {
		return fmt.Errorf("read server response: %w", err)
	}
	if len(body) > maxClientResponse {
		return fmt.Errorf("server response exceeds %d bytes", maxClientResponse)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("server returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	if !json.Valid(body) {
		return errors.New("server returned invalid JSON")
	}

	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		return fmt.Errorf("format server response: %w", err)
	}
	pretty.WriteByte('\n')
	if _, err := pretty.WriteTo(output); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func runHealthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := flags.String("url", envOrDefault("BANNERFP_HEALTH_URL", "http://127.0.0.1:8080/health"), "health endpoint URL")
	timeout := flags.Duration("timeout", 2*time.Second, "health request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("healthcheck: unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *timeout <= 0 {
		return errors.New("healthcheck: --timeout must be positive")
	}

	client := &http.Client{Timeout: *timeout}
	response, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unhealthy HTTP status: %s", response.Status)
	}
	return nil
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func usageError() error {
	return errors.New(usage())
}

func usage() string {
	return `Usage:
  bannerfp serve [--addr :8080] [--rules /path/to/rules.json]
  bannerfp client --input /path/to/input.json [--server http://server:8080]
  bannerfp healthcheck [--url http://127.0.0.1:8080/health]
`
}
