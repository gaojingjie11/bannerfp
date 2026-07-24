package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gaojingjie11/bannerfp/internal/fingerprint"
)

type stubRecognizer struct{}

func (stubRecognizer) Recognize(input fingerprint.Input) fingerprint.Result {
	switch input.Banner {
	case "known":
		return fingerprint.Result{
			IP:         input.IP,
			Port:       input.Port,
			Protocol:   "HTTP",
			Product:    "nginx",
			Version:    "1.24.0",
			Confidence: 0.9,
		}
	default:
		return fingerprint.Result{
			IP:       input.IP,
			Port:     input.Port,
			Protocol: "unknown",
		}
	}
}

func TestHealth(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()

	NewHandler(stubRecognizer{}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	if got := response.Body.String(); got != "{\"status\":\"ok\"}\n" {
		t.Fatalf("body = %q", got)
	}
}

func TestExactRoutesAndMethods(t *testing.T) {
	handler := NewHandler(stubRecognizer{})
	tests := []struct {
		name        string
		method      string
		path        string
		wantStatus  int
		wantAllow   string
		wantErrCode string
	}{
		{name: "health wrong method", method: http.MethodPost, path: "/health", wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodGet, wantErrCode: "method_not_allowed"},
		{name: "fingerprint wrong method", method: http.MethodGet, path: "/fingerprint", wantStatus: http.StatusMethodNotAllowed, wantAllow: http.MethodPost, wantErrCode: "method_not_allowed"},
		{name: "health suffix", method: http.MethodGet, path: "/health/", wantStatus: http.StatusNotFound, wantErrCode: "not_found"},
		{name: "fingerprint suffix", method: http.MethodPost, path: "/fingerprint/extra", wantStatus: http.StatusNotFound, wantErrCode: "not_found"},
		{name: "unknown route", method: http.MethodGet, path: "/", wantStatus: http.StatusNotFound, wantErrCode: "not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if got := response.Header().Get("Allow"); got != test.wantAllow {
				t.Fatalf("Allow = %q, want %q", got, test.wantAllow)
			}
			assertErrorCode(t, response.Body.Bytes(), test.wantErrCode)
		})
	}
}

func TestFingerprintRejectsInvalidEnvelopes(t *testing.T) {
	handler := NewHandler(stubRecognizer{})
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
		wantCode    string
	}{
		{name: "missing content type", body: `[]`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "wrong content type", contentType: "text/plain", body: `[]`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "bad content type", contentType: "application/json; charset", body: `[]`, wantStatus: http.StatusUnsupportedMediaType, wantCode: "unsupported_media_type"},
		{name: "empty body", contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "null", contentType: "application/json", body: `null`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "object", contentType: "application/json", body: `{}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "wrong field type", contentType: "application/json", body: `[{"port":"22"}]`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "trailing null", contentType: "application/json", body: `[] null`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
		{name: "trailing object", contentType: "application/json", body: `[] {}`, wantStatus: http.StatusBadRequest, wantCode: "invalid_json"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.wantStatus, response.Body.String())
			}
			assertErrorCode(t, response.Body.Bytes(), test.wantCode)
		})
	}
}

func TestFingerprintAcceptsJSONParametersAndPreservesMixedBatchOrder(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[
		{"ip":"192.0.2.1","port":80,"banner":"known","scanner_metadata":{"source":"fixture"}},
		{"ip":"192.0.2.2","port":9,"banner":"not known"},
		{}
	]`))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	response := httptest.NewRecorder()

	NewHandler(stubRecognizer{}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(response.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}
	if results[0].IP != "192.0.2.1" || results[0].Protocol != "HTTP" || results[0].Product != "nginx" {
		t.Errorf("result[0] = %#v", results[0])
	}
	if results[1].IP != "192.0.2.2" || results[1].Protocol != "unknown" {
		t.Errorf("result[1] = %#v", results[1])
	}
	if results[2].Protocol != "unknown" {
		t.Errorf("result[2] = %#v; missing fields must remain an item-level unknown", results[2])
	}
}

func TestFingerprintEmptyBatchReturnsEmptyArray(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(`[]`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	NewHandler(stubRecognizer{}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	if got := response.Body.String(); got != "[]\n" {
		t.Fatalf("body = %q, want an empty JSON array", got)
	}
}

func TestFingerprintRejectsOversizedBodyAndBatch(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		body := bytes.NewBuffer(make([]byte, 0, maxRequestBytes+2))
		body.WriteByte('[')
		body.Write(bytes.Repeat([]byte{' '}, maxRequestBytes))
		body.WriteByte(']')
		request := httptest.NewRequest(http.MethodPost, "/fingerprint", body)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		NewHandler(stubRecognizer{}).ServeHTTP(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413; body = %s", response.Code, response.Body.String())
		}
		assertErrorCode(t, response.Body.Bytes(), "request_too_large")
	})

	t.Run("batch", func(t *testing.T) {
		var body strings.Builder
		body.WriteByte('[')
		for i := 0; i < maxBatchSize+1; i++ {
			if i > 0 {
				body.WriteByte(',')
			}
			body.WriteString(`{}`)
		}
		body.WriteByte(']')
		request := httptest.NewRequest(http.MethodPost, "/fingerprint", strings.NewReader(body.String()))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()

		NewHandler(stubRecognizer{}).ServeHTTP(response, request)

		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413; body = %s", response.Code, response.Body.String())
		}
		assertErrorCode(t, response.Body.Bytes(), "batch_too_large")
	})
}

func TestConcurrentFingerprintAndContinuedHealth(t *testing.T) {
	handler := NewHandler(stubRecognizer{})
	server := httptest.NewServer(handler)
	defer server.Close()

	const workers = 32
	var wg sync.WaitGroup
	errors := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`[{"ip":"192.0.2.%d","port":80,"banner":"known"}]`, i)
			response, err := http.Post(server.URL+"/fingerprint", "application/json", strings.NewReader(body))
			if err != nil {
				errors <- err
				return
			}
			defer func() {
				_ = response.Body.Close()
			}()
			if response.StatusCode != http.StatusOK {
				errors <- fmt.Errorf("worker %d status = %d", i, response.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}

	// A malformed request must not poison the process or its readiness endpoint.
	response, err := http.Post(server.URL+"/fingerprint", "application/json", strings.NewReader(`null`))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed request status = %d", response.StatusCode)
	}

	response, err = http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status after traffic = %d, want 200", response.StatusCode)
	}
}

func assertErrorCode(t *testing.T, body []byte, want string) {
	t.Helper()
	var response errorResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("error response is not JSON: %v; body = %q", err, body)
	}
	if response.Error.Code != want {
		t.Fatalf("error code = %q, want %q; body = %s", response.Error.Code, want, body)
	}
}
