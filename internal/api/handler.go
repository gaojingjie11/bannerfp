// Package api exposes the HTTP transport for the fingerprint engine.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/gaojingjie11/bannerfp/internal/fingerprint"
)

const (
	maxRequestBytes = 8 << 20
	maxBatchSize    = 10_000
)

// Recognizer is the part of the fingerprint engine used by the HTTP layer.
// Keeping this as a small interface makes the transport independently testable.
type Recognizer interface {
	Recognize(fingerprint.Input) fingerprint.Result
}

// Handler implements the service's exact HTTP routes.
type Handler struct {
	recognizer Recognizer
}

// NewHandler builds a concurrency-safe HTTP handler around recognizer.
func NewHandler(recognizer Recognizer) http.Handler {
	if recognizer == nil {
		panic("api: nil recognizer")
	}
	return &Handler{recognizer: recognizer}
}

// New is a concise alias for NewHandler.
func New(recognizer Recognizer) http.Handler {
	return NewHandler(recognizer)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.health(w)
	case "/fingerprint":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		h.fingerprint(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "route not found")
	}
}

func (h *Handler) health(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(r.Body)

	var inputs []fingerprint.Input
	if err := decoder.Decode(&inputs); err != nil {
		writeDecodeError(w, err)
		return
	}
	if inputs == nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be a JSON array")
		return
	}
	if len(inputs) > maxBatchSize {
		writeError(w, http.StatusRequestEntityTooLarge, "batch_too_large", "batch must contain at most 10000 items")
		return
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err != nil {
			writeDecodeError(w, err)
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain exactly one JSON value")
		}
		return
	}

	results := make([]fingerprint.Result, len(inputs))
	for i, input := range inputs {
		results[i] = h.recognizer.Recognize(input)
	}
	writeJSON(w, http.StatusOK, results)
}

func isJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 8 MiB")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_json", "request body must be a JSON array of fingerprint inputs")
}

type errorResponse struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{
		Error: errorDetail{
			Code:    code,
			Message: message,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
