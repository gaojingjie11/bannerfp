// Package fingerprint identifies services from raw network banners.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const maxRulesFileSize = 4 << 20

var httpStatusLinePattern = regexp.MustCompile(`(?i)^HTTP/[0-9]+(?:\.[0-9]+)?[ \t]+[0-9]{3}(?:[ \t]|$)`)

// Input is a single raw scan observation.
type Input struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the normalized fingerprint for one input.
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Rule is one externally configured fingerprint rule.
//
// Rules are evaluated in file order. Pattern uses Go's RE2 syntax and may
// define named capture groups called "version" and "os".
type Rule struct {
	ID         string  `json:"id"`
	Scope      string  `json:"scope"`
	Pattern    string  `json:"pattern"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product,omitempty"`
	Confidence float64 `json:"confidence"`
}

// Engine is an immutable, concurrency-safe ordered ruleset.
type Engine struct {
	rules []compiledRule
}

type rulesDocument struct {
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

type compiledRule struct {
	rule         Rule
	pattern      *regexp.Regexp
	versionIndex int
	osIndex      int
}

// LoadFile loads, validates, and compiles an external rules file.
func LoadFile(path string) (*Engine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	engine, err := Load(file)
	if err != nil {
		return nil, fmt.Errorf("load rules file: %w", err)
	}
	return engine, nil
}

// Load validates and compiles ordered rules from a JSON object or array.
func Load(reader io.Reader) (*Engine, error) {
	if reader == nil {
		return nil, errors.New("load rules: nil reader")
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxRulesFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	if len(data) > maxRulesFileSize {
		return nil, fmt.Errorf("read rules: file exceeds %d bytes", maxRulesFileSize)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("decode rules: empty document")
	}

	document := rulesDocument{Version: 1}
	switch data[0] {
	case '{':
		if err := decodeSingleJSON(data, &document); err != nil {
			return nil, fmt.Errorf("decode rules: %w", err)
		}
	case '[':
		if err := decodeSingleJSON(data, &document.Rules); err != nil {
			return nil, fmt.Errorf("decode rules: %w", err)
		}
	default:
		return nil, errors.New("decode rules: top-level value must be an object or array")
	}

	if document.Version != 1 {
		return nil, fmt.Errorf("validate rules: unsupported schema version %d", document.Version)
	}
	if len(document.Rules) == 0 {
		return nil, errors.New("validate rules: at least one rule is required")
	}

	compiled := make([]compiledRule, 0, len(document.Rules))
	ids := make(map[string]struct{}, len(document.Rules))
	for index, rule := range document.Rules {
		compiledRule, err := compileRule(rule, ids)
		if err != nil {
			return nil, fmt.Errorf("validate rule %d: %w", index, err)
		}
		compiled = append(compiled, compiledRule)
	}
	return &Engine{rules: compiled}, nil
}

// Recognize identifies one input. An unmatched or malformed banner always
// returns a neutral unknown result and never depends on the input port.
func (e *Engine) Recognize(input Input) Result {
	result := Result{
		IP:       input.IP,
		Port:     input.Port,
		Protocol: "unknown",
	}
	if e == nil {
		return result
	}

	firstLine := ""
	firstLineReady := false
	headers := ""
	headersReady := false
	headersValid := false

	for _, rule := range e.rules {
		var candidate string
		switch rule.rule.Scope {
		case "banner":
			candidate = input.Banner
		case "first_line":
			if !firstLineReady {
				firstLine = extractFirstLine(input.Banner)
				firstLineReady = true
			}
			candidate = firstLine
		case "http_headers":
			if !headersReady {
				headers, headersValid = extractHTTPHeaders(input.Banner)
				headersReady = true
			}
			if !headersValid {
				continue
			}
			candidate = headers
		}

		matches := rule.pattern.FindStringSubmatch(candidate)
		if matches == nil {
			continue
		}

		result.Protocol = rule.rule.Protocol
		result.Product = rule.rule.Product
		result.Confidence = rule.rule.Confidence
		result.Version = namedMatch(matches, rule.versionIndex)
		result.OSHint = namedMatch(matches, rule.osIndex)
		return result
	}
	return result
}

func decodeSingleJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}

	var trailing any
	err := decoder.Decode(&trailing)
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func compileRule(rule Rule, ids map[string]struct{}) (compiledRule, error) {
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		return compiledRule{}, errors.New("id is required")
	}
	if _, exists := ids[rule.ID]; exists {
		return compiledRule{}, fmt.Errorf("duplicate id %q", rule.ID)
	}
	ids[rule.ID] = struct{}{}

	switch rule.Scope {
	case "banner", "first_line", "http_headers":
	default:
		return compiledRule{}, fmt.Errorf("unsupported scope %q", rule.Scope)
	}
	if rule.Pattern == "" {
		return compiledRule{}, errors.New("pattern is required")
	}
	if strings.TrimSpace(rule.Protocol) == "" {
		return compiledRule{}, errors.New("protocol is required")
	}
	if rule.Confidence < 0 || rule.Confidence > 1 {
		return compiledRule{}, fmt.Errorf("confidence %v is outside 0..1", rule.Confidence)
	}

	pattern, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return compiledRule{}, fmt.Errorf("compile pattern: %w", err)
	}
	return compiledRule{
		rule:         rule,
		pattern:      pattern,
		versionIndex: pattern.SubexpIndex("version"),
		osIndex:      pattern.SubexpIndex("os"),
	}, nil
}

func namedMatch(matches []string, index int) string {
	if index <= 0 || index >= len(matches) {
		return ""
	}
	return strings.TrimSpace(matches[index])
}

func extractFirstLine(banner string) string {
	if index := strings.IndexAny(banner, "\r\n"); index >= 0 {
		return banner[:index]
	}
	return banner
}

func extractHTTPHeaders(banner string) (string, bool) {
	lineEnd, next := lineBoundary(banner, 0)
	if lineEnd == 0 || !httpStatusLinePattern.MatchString(banner[:lineEnd]) {
		return "", false
	}

	for next < len(banner) {
		end, following := lineBoundary(banner, next)
		if end == next {
			return banner[:next], true
		}
		next = following
	}
	return banner, true
}

func lineBoundary(value string, start int) (end, next int) {
	if start >= len(value) {
		return len(value), len(value)
	}
	offset := strings.IndexAny(value[start:], "\r\n")
	if offset < 0 {
		return len(value), len(value)
	}

	end = start + offset
	next = end + 1
	if value[end] == '\r' && next < len(value) && value[next] == '\n' {
		next++
	}
	return end, next
}
