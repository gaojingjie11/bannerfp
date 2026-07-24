package fingerprint

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestDefaultRulesRecognizeProducts(t *testing.T) {
	t.Parallel()

	engine := loadDefaultEngine(t)
	tests := []struct {
		name       string
		banner     string
		protocol   string
		product    string
		version    string
		osHint     string
		confidence float64
	}{
		{
			name:       "OpenSSH Ubuntu",
			banner:     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
			protocol:   "SSH",
			product:    "OpenSSH",
			version:    "8.9p1",
			osHint:     "Ubuntu",
			confidence: 0.95,
		},
		{
			name:       "OpenSSH Debian legacy protocol",
			banner:     "SSH-1.99-OpenSSH_4.3 Debian-10",
			protocol:   "SSH",
			product:    "OpenSSH",
			version:    "4.3",
			osHint:     "Debian",
			confidence: 0.95,
		},
		{
			name:       "Dropbear",
			banner:     "SSH-2.0-dropbear_2022.83",
			protocol:   "SSH",
			product:    "Dropbear",
			version:    "2022.83",
			confidence: 0.92,
		},
		{
			name:       "OpenSSH for Windows",
			banner:     "SSH-2.0-OpenSSH_for_Windows_9.5",
			protocol:   "SSH",
			product:    "OpenSSH",
			version:    "9.5",
			osHint:     "Windows",
			confidence: 0.95,
		},
		{
			name:       "nginx LF and spaces",
			banner:     "HTTP/1.1 200 OK\nDate: now\nserver : nginx/1.25.4 (Ubuntu)\nContent-Length: 0",
			protocol:   "HTTP",
			product:    "nginx",
			version:    "1.25.4",
			osHint:     "Ubuntu",
			confidence: 0.90,
		},
		{
			name:       "Apache",
			banner:     "HTTP/1.0 403 Forbidden\r\nServer:\tApache/2.4.62 (Unix)\r\n\r\n",
			protocol:   "HTTP",
			product:    "Apache",
			version:    "2.4.62",
			osHint:     "Unix",
			confidence: 0.90,
		},
		{
			name:       "Jetty parenthesized version",
			banner:     "HTTP/1.1 404 Not Found\r\nSERVER: Jetty(12.0.12)\r\n\r\n",
			protocol:   "HTTP",
			product:    "Jetty",
			version:    "12.0.12",
			confidence: 0.85,
		},
		{
			name:       "IIS",
			banner:     "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n",
			protocol:   "HTTP",
			product:    "Microsoft-IIS",
			version:    "10.0",
			confidence: 0.90,
		},
		{
			name:       "OpenResty",
			banner:     "HTTP/2 200\r\nserver: openresty/1.25.3.1\r\n\r\n",
			protocol:   "HTTP",
			product:    "OpenResty",
			version:    "1.25.3.1",
			confidence: 0.90,
		},
		{
			name:       "Caddy no version",
			banner:     "HTTP/1.1 200 OK\r\nServer: Caddy\r\n\r\n",
			protocol:   "HTTP",
			product:    "Caddy",
			confidence: 0.85,
		},
		{
			name:       "lighttpd",
			banner:     "HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.76\r\n\r\n",
			protocol:   "HTTP",
			product:    "lighttpd",
			version:    "1.4.76",
			confidence: 0.90,
		},
		{
			name:       "MariaDB handshake",
			banner:     mysqlHandshake("5.5.5-10.11.8-MariaDB-0ubuntu0.24.04.1"),
			protocol:   "MySQL",
			product:    "MariaDB",
			version:    "10.11.8",
			confidence: 0.90,
		},
		{
			name:       "MySQL handshake",
			banner:     mysqlHandshake("8.4.2"),
			protocol:   "MySQL",
			product:    "MySQL",
			version:    "8.4.2",
			confidence: 0.90,
		},
		{
			name:       "Redis PONG",
			banner:     "+PONG\r\n",
			protocol:   "Redis",
			product:    "Redis",
			confidence: 0.70,
		},
		{
			name:       "Redis INFO version",
			banner:     "$123\r\n# Server\r\nredis_version:7.2.5\r\nredis_mode:standalone\r\n",
			protocol:   "Redis",
			product:    "Redis",
			version:    "7.2.5",
			confidence: 0.92,
		},
		{
			name:       "ProFTPD",
			banner:     "220 ProFTPD 1.3.7 Server (ProFTPD)\r\n",
			protocol:   "FTP",
			product:    "ProFTPD",
			version:    "1.3.7",
			confidence: 0.90,
		},
		{
			name:       "vsFTPd",
			banner:     "220 (vsFTPd 3.0.5)\n",
			protocol:   "FTP",
			product:    "vsFTPd",
			version:    "3.0.5",
			confidence: 0.90,
		},
		{
			name:       "Pure-FTPd no version",
			banner:     "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\r\n",
			protocol:   "FTP",
			product:    "Pure-FTPd",
			confidence: 0.90,
		},
		{
			name:       "FileZilla Server",
			banner:     "220-FileZilla Server 1.9.4\r\n",
			protocol:   "FTP",
			product:    "FileZilla Server",
			version:    "1.9.4",
			confidence: 0.90,
		},
		{
			name:       "TLS record",
			banner:     "\x16\x03\x03\x00\xa5\x01\x00\x00\xa1",
			protocol:   "TLS",
			confidence: 0.65,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := engine.Recognize(Input{
				IP:     "203.0.113.9",
				Port:   49152,
				Banner: tt.banner,
			})
			assertResult(t, got, Result{
				IP:         "203.0.113.9",
				Port:       49152,
				Protocol:   tt.protocol,
				Product:    tt.product,
				Version:    tt.version,
				OSHint:     tt.osHint,
				Confidence: tt.confidence,
			})
		})
	}
}

func TestRecognizeGenericProtocolsAndUnknown(t *testing.T) {
	t.Parallel()

	engine := loadDefaultEngine(t)
	tests := []struct {
		name     string
		banner   string
		protocol string
	}{
		{name: "generic SSH", banner: "SSH-2.0-AcmeSSH_1.0", protocol: "SSH"},
		{name: "generic HTTP", banner: "HTTP/1.1 204 No Content\r\nX-Test: yes\r\n", protocol: "HTTP"},
		{name: "Redis authentication", banner: "-NOAUTH Authentication required.", protocol: "Redis"},
		{name: "Redis command error", banner: "-ERR wrong number of arguments for 'get' command", protocol: "Redis"},
		{name: "generic FTP", banner: "220 Welcome to Acme FTP service\r\n", protocol: "FTP"},
		{name: "empty", banner: "", protocol: "unknown"},
		{name: "arbitrary", banner: "QUIT\r\n", protocol: "unknown"},
		{name: "SMTP is not FTP", banner: "220 smtp.example ESMTP Postfix\r\n", protocol: "unknown"},
		{name: "HTTP token not status line", banner: "hello HTTP/1.1 200 OK", protocol: "unknown"},
		{name: "truncated TLS", banner: "\x16\x03\x03\x00", protocol: "unknown"},
		{name: "truncated MySQL", banner: "\x4a\x00\x00\x00\x0a", protocol: "unknown"},
		{name: "MySQL nonzero sequence ID", banner: "\x10\x00\x00\x01\x0a" + "8.0.0\x00", protocol: "unknown"},
		{name: "arbitrary binary", banner: "\x00\xff\xfe\x10\x80", protocol: "unknown"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := engine.Recognize(Input{
				IP:     "198.51.100.8",
				Port:   1,
				Banner: tt.banner,
			})
			if got.Protocol != tt.protocol {
				t.Fatalf("Recognize(%q) protocol = %q, want %q", tt.banner, got.Protocol, tt.protocol)
			}
			if got.IP != "198.51.100.8" || got.Port != 1 {
				t.Fatalf("Recognize(%q) identity = %s:%d, want 198.51.100.8:1", tt.banner, got.IP, got.Port)
			}
			if tt.protocol == "unknown" {
				assertResult(t, got, Result{
					IP:       "198.51.100.8",
					Port:     1,
					Protocol: "unknown",
				})
			}
		})
	}
}

func TestRecognizeDoesNotDependOnPort(t *testing.T) {
	t.Parallel()

	engine := loadDefaultEngine(t)
	for _, port := range []int{0, 21, 22, 80, 443, 3306, 6379, 65535} {
		got := engine.Recognize(Input{
			IP:     "192.0.2.44",
			Port:   port,
			Banner: "SSH-2.0-OpenSSH_9.8",
		})
		if got.Protocol != "SSH" || got.Product != "OpenSSH" || got.Version != "9.8" {
			t.Fatalf("port %d changed classification: %+v", port, got)
		}
		if got.Port != port {
			t.Fatalf("port identity = %d, want %d", got.Port, port)
		}
	}
}

func TestHTTPBodyCannotForgeServerHeader(t *testing.T) {
	t.Parallel()

	engine := loadDefaultEngine(t)
	tests := []string{
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: nginx/9.9.9\r\n",
		"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nServer: Apache/9.9.9\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<div>Server: Jetty/9.9.9</div>",
	}
	for _, banner := range tests {
		got := engine.Recognize(Input{Banner: banner})
		if got.Protocol != "HTTP" || got.Product != "" || got.Version != "" {
			t.Fatalf("forged body server header classified as product: %+v", got)
		}
	}
}

func TestRuleOrderWins(t *testing.T) {
	t.Parallel()

	engine, err := Load(strings.NewReader(`{
		"version": 1,
		"rules": [
			{"id":"specific","scope":"banner","pattern":"^same$","protocol":"first","product":"one","confidence":0.9},
			{"id":"generic","scope":"banner","pattern":"^same$","protocol":"second","product":"two","confidence":0.8}
		]
	}`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := engine.Recognize(Input{Banner: "same"})
	if got.Protocol != "first" || got.Product != "one" {
		t.Fatalf("ordered rules result = %+v, want first rule", got)
	}
}

func TestNamedCaptureExtraction(t *testing.T) {
	t.Parallel()

	engine, err := Load(strings.NewReader(`[
		{
			"id":"captures",
			"scope":"first_line",
			"pattern":"^Thing/(?P<version>[0-9.]+)[ ]+[(](?P<os>[^)]+)[)]$",
			"protocol":"P",
			"product":"Thing",
			"confidence":1
		}
	]`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	got := engine.Recognize(Input{Banner: "Thing/2.7.1 (Plan 9)\r\nignored"})
	if got.Version != "2.7.1" || got.OSHint != "Plan 9" {
		t.Fatalf("named captures result = %+v", got)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{name: "empty rules", data: `{"version":1,"rules":[]}`},
		{name: "unsupported schema", data: `{"version":2,"rules":[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":1}]}`},
		{name: "duplicate ID", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":1},{"id":"x","scope":"banner","pattern":"y","protocol":"y","confidence":1}]}`},
		{name: "empty ID", data: `{"version":1,"rules":[{"scope":"banner","pattern":"x","protocol":"x","confidence":1}]}`},
		{name: "bad scope", data: `{"version":1,"rules":[{"id":"x","scope":"body","pattern":"x","protocol":"x","confidence":1}]}`},
		{name: "bad regexp", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"(","protocol":"x","confidence":1}]}`},
		{name: "empty protocol", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"x","confidence":1}]}`},
		{name: "confidence low", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":-0.1}]}`},
		{name: "confidence high", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":1.1}]}`},
		{name: "trailing JSON", data: `[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":1}] {}`},
		{name: "unknown field", data: `{"version":1,"rules":[{"id":"x","scope":"banner","pattern":"x","protocol":"x","confidence":1,"typo":true}]}`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Load(strings.NewReader(tt.data)); err == nil {
				t.Fatalf("Load(%s) error = nil, want validation error", tt.data)
			}
		})
	}
}

func TestConcurrentRecognize(t *testing.T) {
	t.Parallel()

	engine := loadDefaultEngine(t)
	inputs := []Input{
		{IP: "192.0.2.1", Port: 50000, Banner: "SSH-2.0-OpenSSH_9.9 Debian-1"},
		{IP: "192.0.2.2", Port: 50001, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.26.1\r\n\r\n"},
		{IP: "192.0.2.3", Port: 50002, Banner: mysqlHandshake("9.1.0")},
		{IP: "192.0.2.4", Port: 50003, Banner: "+PONG"},
		{IP: "192.0.2.5", Port: 50004, Banner: "unrecognized"},
	}
	wantProtocols := []string{"SSH", "HTTP", "MySQL", "Redis", "unknown"}

	const goroutines = 32
	const iterations = 200
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for worker := 0; worker < goroutines; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				index := i % len(inputs)
				got := engine.Recognize(inputs[index])
				if got.Protocol != wantProtocols[index] {
					errs <- fmt.Errorf("input %d protocol = %q, want %q", index, got.Protocol, wantProtocols[index])
					return
				}
				if got.IP != inputs[index].IP || got.Port != inputs[index].Port {
					errs <- fmt.Errorf("input %d identity = %s:%d, want %s:%d",
						index, got.IP, got.Port, inputs[index].IP, inputs[index].Port)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func loadDefaultEngine(t *testing.T) *Engine {
	t.Helper()

	engine, err := LoadFile("../../rules/default.json")
	if err != nil {
		t.Fatalf("LoadFile(default rules) error = %v", err)
	}
	return engine
}

func mysqlHandshake(version string) string {
	payload := append([]byte{0x0a}, version...)
	payload = append(payload, 0x00, 0x2a, 0x00, 0x00, 0x00)
	length := len(payload)
	packet := []byte{byte(length), byte(length >> 8), byte(length >> 16), 0x00}
	packet = append(packet, payload...)
	return string(packet)
}

func assertResult(t *testing.T, got, want Result) {
	t.Helper()

	if got != want {
		t.Fatalf("result = %+v, want %+v", got, want)
	}
}
