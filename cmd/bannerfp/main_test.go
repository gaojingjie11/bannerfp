package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunClientPostsInputAndPrintsPrettyJSON(t *testing.T) {
	t.Parallel()

	inputPath := filepath.Join(t.TempDir(), "input.json")
	input := `[{"ip":"192.0.2.1","port":22,"banner":"SSH-2.0-test"}]`
	if err := os.WriteFile(inputPath, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	var gotContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" {
			t.Errorf("request = %s %s, want POST /fingerprint", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"protocol":"SSH","confidence":0.7}]`))
	}))
	defer server.Close()

	var output bytes.Buffer
	err := runClient([]string{"--server", server.URL + "/", "--input", inputPath}, &output)
	if err != nil {
		t.Fatalf("runClient() error = %v", err)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	if !strings.Contains(output.String(), "\n  {\n") || !strings.HasSuffix(output.String(), "\n") {
		t.Fatalf("output is not pretty JSON with trailing newline: %q", output.String())
	}
}

func TestRunClientRejectsBadLocalJSON(t *testing.T) {
	t.Parallel()

	inputPath := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(inputPath, []byte(`not JSON`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runClient([]string{"--server", "http://127.0.0.1:1", "--input", inputPath}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("runClient() error = %v, want invalid JSON error", err)
	}
}

func TestRunHealthcheck(t *testing.T) {
	t.Parallel()

	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	if err := runHealthcheck([]string{"--url", healthy.URL}); err != nil {
		t.Fatalf("healthy runHealthcheck() error = %v", err)
	}

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()
	if err := runHealthcheck([]string{"--url", unhealthy.URL}); err == nil {
		t.Fatal("unhealthy runHealthcheck() error = nil")
	}
}

func TestRunRequiresKnownCommand(t *testing.T) {
	t.Parallel()

	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("run(nil) error = nil")
	}
	if err := run([]string{"unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("run(unknown) error = nil")
	}
}
