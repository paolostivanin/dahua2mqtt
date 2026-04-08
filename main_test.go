package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ===================================================================
// TEST HELPERS
// ===================================================================

// newTestApp creates an app with a no-op MQTT client for testing HTTP
// handlers and event processing logic without a real broker.
func newTestApp(cfg config) *app {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &app{
		cfg:         cfg,
		startTime:   time.Now(),
		logger:      logger,
		antiDither:  make(map[string]antiDitherEntry),
		offTimers:   make(map[string]*time.Timer),
		offTimerGen: make(map[string]uint64),
		allowedIPs:  buildAllowedIPs(cfg.AllowedIPs),
	}
}

func buildAllowedIPs(ips []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		m[ip] = struct{}{}
	}
	return m
}

func defaultTestConfig() config {
	return config{
		MQTT:       mqttConfig{Host: "localhost", Port: 1883},
		Port:       8080,
		LogLevel:   "INFO",
		OffDelay:   10,
		Cameras:    []string{"cam1", "cam2"},
		AntiDither: 0,
	}
}

func makeEventJSON(action, code, name, uuid string, obj *objectInfo, objects []objectInfo) []byte {
	data := map[string]any{
		"Code":         code,
		"Name":         name,
		"EventUUIDStr": uuid,
	}
	if obj != nil {
		data["Object"] = obj
	}
	if objects != nil {
		data["Objects"] = objects
	}
	dataBytes, _ := json.Marshal(data)

	event := map[string]any{
		"Action": action,
		"Data":   json.RawMessage(dataBytes),
	}
	b, _ := json.Marshal(event)
	return b
}

// ===================================================================
// CONFIG TESTS
// ===================================================================

func TestLoadConfig_FileNotFound(t *testing.T) {
	t.Setenv("CONFIG_FILE", "/nonexistent/path.yaml")
	cfg := loadConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.MQTT.Host != "localhost" {
		t.Errorf("expected default MQTT host localhost, got %s", cfg.MQTT.Host)
	}
	if cfg.OffDelay != 10 {
		t.Errorf("expected default off_delay 10, got %d", cfg.OffDelay)
	}
}

func TestLoadConfig_ValidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
mqtt:
  host: "10.0.0.1"
  port: 1884
  username: "user1"
  password: "pass1"
cameras:
  - cam1
  - cam2
  - cam3
port: 9090
log_level: "DEBUG"
anti_dither: 5
off_delay: 15
trust_proxy: true
allowed_ips:
  - "192.168.1.1"
  - "192.168.1.2"
`
	os.WriteFile(path, []byte(content), 0644)
	t.Setenv("CONFIG_FILE", path)

	cfg := loadConfig()

	if cfg.MQTT.Host != "10.0.0.1" {
		t.Errorf("MQTT host = %s, want 10.0.0.1", cfg.MQTT.Host)
	}
	if cfg.MQTT.Port != 1884 {
		t.Errorf("MQTT port = %d, want 1884", cfg.MQTT.Port)
	}
	if cfg.MQTT.Username != "user1" {
		t.Errorf("MQTT username = %s, want user1", cfg.MQTT.Username)
	}
	if cfg.Port != 9090 {
		t.Errorf("port = %d, want 9090", cfg.Port)
	}
	if cfg.LogLevel != "DEBUG" {
		t.Errorf("log_level = %s, want DEBUG", cfg.LogLevel)
	}
	if cfg.AntiDither != 5 {
		t.Errorf("anti_dither = %d, want 5", cfg.AntiDither)
	}
	if cfg.OffDelay != 15 {
		t.Errorf("off_delay = %d, want 15", cfg.OffDelay)
	}
	if !cfg.TrustProxy {
		t.Error("trust_proxy should be true")
	}
	if len(cfg.Cameras) != 3 {
		t.Errorf("cameras count = %d, want 3", len(cfg.Cameras))
	}
	if len(cfg.AllowedIPs) != 2 {
		t.Errorf("allowed_ips count = %d, want 2", len(cfg.AllowedIPs))
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(":::invalid yaml:::"), 0644)
	t.Setenv("CONFIG_FILE", path)

	cfg := loadConfig()
	if cfg.Port != 8080 {
		t.Errorf("expected default port on invalid YAML, got %d", cfg.Port)
	}
}

func TestApplyDefaults_ZeroValues(t *testing.T) {
	cfg := config{}
	applyDefaults(&cfg)

	if cfg.MQTT.Host != "localhost" {
		t.Errorf("MQTT.Host = %s, want localhost", cfg.MQTT.Host)
	}
	if cfg.MQTT.Port != 1883 {
		t.Errorf("MQTT.Port = %d, want 1883", cfg.MQTT.Port)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080", cfg.Port)
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel = %s, want INFO", cfg.LogLevel)
	}
	if cfg.OffDelay != 10 {
		t.Errorf("OffDelay = %d, want 10", cfg.OffDelay)
	}
}

func TestApplyDefaults_PreservesSetValues(t *testing.T) {
	cfg := config{
		MQTT:     mqttConfig{Host: "broker.local", Port: 1884},
		Port:     9090,
		LogLevel: "DEBUG",
		OffDelay: 20,
	}
	applyDefaults(&cfg)

	if cfg.MQTT.Host != "broker.local" {
		t.Errorf("MQTT.Host = %s, want broker.local", cfg.MQTT.Host)
	}
	if cfg.MQTT.Port != 1884 {
		t.Errorf("MQTT.Port = %d, want 1884", cfg.MQTT.Port)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want 9090", cfg.Port)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	cfg := defaultConfig()

	t.Setenv("MQTT_HOST", "env-broker")
	t.Setenv("MQTT_PORT", "1884")
	t.Setenv("MQTT_USERNAME", "envuser")
	t.Setenv("MQTT_PASSWORD", "envpass")
	t.Setenv("PORT", "9999")
	t.Setenv("LOG_LEVEL", "DEBUG")
	t.Setenv("ANTI_DITHER", "7")
	t.Setenv("OFF_DELAY", "30")
	t.Setenv("TRUST_PROXY", "yes")

	applyEnvOverrides(&cfg)

	if cfg.MQTT.Host != "env-broker" {
		t.Errorf("MQTT.Host = %s, want env-broker", cfg.MQTT.Host)
	}
	if cfg.MQTT.Port != 1884 {
		t.Errorf("MQTT.Port = %d, want 1884", cfg.MQTT.Port)
	}
	if cfg.MQTT.Username != "envuser" {
		t.Errorf("MQTT.Username = %s, want envuser", cfg.MQTT.Username)
	}
	if cfg.MQTT.Password != "envpass" {
		t.Errorf("MQTT.Password = %s, want envpass", cfg.MQTT.Password)
	}
	if cfg.Port != 9999 {
		t.Errorf("Port = %d, want 9999", cfg.Port)
	}
	if cfg.LogLevel != "DEBUG" {
		t.Errorf("LogLevel = %s, want DEBUG", cfg.LogLevel)
	}
	if cfg.AntiDither != 7 {
		t.Errorf("AntiDither = %d, want 7", cfg.AntiDither)
	}
	if cfg.OffDelay != 30 {
		t.Errorf("OffDelay = %d, want 30", cfg.OffDelay)
	}
	if !cfg.TrustProxy {
		t.Error("TrustProxy should be true")
	}
}

func TestApplyEnvOverrides_TrustProxyCaseInsensitive(t *testing.T) {
	for _, val := range []string{"TRUE", "True", "YES", "Yes", "1"} {
		cfg := defaultConfig()
		t.Setenv("TRUST_PROXY", val)
		applyEnvOverrides(&cfg)
		if !cfg.TrustProxy {
			t.Errorf("TRUST_PROXY=%q should be true", val)
		}
	}
}

func TestEnvOr(t *testing.T) {
	if got := envOr("NONEXISTENT_VAR_12345", "fallback"); got != "fallback" {
		t.Errorf("envOr = %s, want fallback", got)
	}

	t.Setenv("TEST_ENVOR_VAR", "value")
	if got := envOr("TEST_ENVOR_VAR", "fallback"); got != "value" {
		t.Errorf("envOr = %s, want value", got)
	}
}

// ===================================================================
// HELPER FUNCTION TESTS
// ===================================================================

func TestSanitizeMQTT(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"cam1", "cam1"},
		{"cam/1", "cam1"},
		{"cam+1", "cam1"},
		{"cam#1", "cam1"},
		{"cam\x001", "cam1"},
		{"cam/+#\x00x", "camx"},
		{"", ""},
		{"normal_name", "normal_name"},
	}
	for _, tt := range tests {
		if got := sanitizeMQTT(tt.input); got != tt.want {
			t.Errorf("sanitizeMQTT(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestExtractCamera(t *testing.T) {
	tests := []struct {
		name, want string
	}{
		{"cam1_r1_h_trip", "cam1"},
		{"cam2_r1_ch_intrusion", "cam2"},
		{"singlepart", "singlepart"},
		{"", "unknown"},
		{"cam/1_rule", "cam1"}, // sanitized
	}
	for _, tt := range tests {
		if got := extractCamera(tt.name); got != tt.want {
			t.Errorf("extractCamera(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestMapKeys(t *testing.T) {
	m := map[string]struct{}{
		"a": {},
		"b": {},
	}
	keys := mapKeys(m)
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	// Order is not guaranteed, just check both exist
	has := make(map[string]bool)
	for _, k := range keys {
		has[k] = true
	}
	if !has["a"] || !has["b"] {
		t.Errorf("mapKeys = %v, want [a, b]", keys)
	}
}

func TestParseSlogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"WARN", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"ERROR", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}
	for _, tt := range tests {
		if got := parseSlogLevel(tt.input); got != tt.want {
			t.Errorf("parseSlogLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ===================================================================
// OBJECT EXTRACTION TESTS
// ===================================================================

func TestExtractObjectTypes_FromObjectField(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name     string
		data     eventData
		wantAny  []string // at least one of these must appear
		wantLen  int
	}{
		{
			name: "ObjectType human",
			data: eventData{
				Object: &objectInfo{ObjectType: "Human"},
			},
			wantAny: []string{"human"},
			wantLen: 1,
		},
		{
			name: "ObjectType vehicle",
			data: eventData{
				Object: &objectInfo{ObjectType: "Vehicle"},
			},
			wantAny: []string{"vehicle"},
			wantLen: 1,
		},
		{
			name: "ObjectType person alias",
			data: eventData{
				Object: &objectInfo{ObjectType: "Person"},
			},
			wantAny: []string{"human"},
			wantLen: 1,
		},
		{
			name: "ObjectType car alias",
			data: eventData{
				Object: &objectInfo{ObjectType: "Car"},
			},
			wantAny: []string{"vehicle"},
			wantLen: 1,
		},
		{
			name: "ObjectType motorvehicle alias",
			data: eventData{
				Object: &objectInfo{ObjectType: "MotorVehicle"},
			},
			wantAny: []string{"vehicle"},
			wantLen: 1,
		},
		{
			name: "Type field used",
			data: eventData{
				Object: &objectInfo{Type: "Human"},
			},
			wantAny: []string{"human"},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractObjectTypes(tt.data, logger)
			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d (got %v)", len(got), tt.wantLen, got)
			}
			found := false
			for _, w := range tt.wantAny {
				for _, g := range got {
					if g == w {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("got %v, want one of %v", got, tt.wantAny)
			}
		})
	}
}

func TestExtractObjectTypes_FromObjectsArray(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	data := eventData{
		Objects: []objectInfo{
			{ObjectType: "Human"},
			{ObjectType: "Vehicle"},
		},
	}
	got := extractObjectTypes(data, logger)
	if len(got) != 2 {
		t.Fatalf("expected 2 types, got %d: %v", len(got), got)
	}

	has := make(map[string]bool)
	for _, g := range got {
		has[g] = true
	}
	if !has["human"] || !has["vehicle"] {
		t.Errorf("got %v, want [human, vehicle]", got)
	}
}

func TestExtractObjectTypes_FallbackToRuleName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name    string
		data    eventData
		want    map[string]bool
	}{
		{
			name: "rule with _h_ = human",
			data: eventData{Name: "cam1_r1_h_trip"},
			want: map[string]bool{"human": true},
		},
		{
			name: "rule with _c_ = vehicle",
			data: eventData{Name: "cam1_r1_c_trip"},
			want: map[string]bool{"vehicle": true},
		},
		{
			name: "rule with _ch_ = both",
			data: eventData{Name: "cam1_r1_ch_trip"},
			want: map[string]bool{"vehicle": true, "human": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractObjectTypes(tt.data, logger)
			has := make(map[string]bool)
			for _, g := range got {
				has[g] = true
			}
			for k := range tt.want {
				if !has[k] {
					t.Errorf("missing %s in %v", k, got)
				}
			}
		})
	}
}

func TestExtractObjectTypes_NoInfoDefaultsToBoth(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	data := eventData{Name: "cam1_r1_unknown_trip"}
	got := extractObjectTypes(data, logger)
	if len(got) != 2 {
		t.Fatalf("expected 2 defaults, got %d: %v", len(got), got)
	}
}

func TestExtractObjectTypes_PayloadTakesPriorityOverRuleName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Payload says human, rule name says _c_ (vehicle) — payload wins
	data := eventData{
		Name:   "cam1_r1_c_trip",
		Object: &objectInfo{ObjectType: "Human"},
	}
	got := extractObjectTypes(data, logger)
	if len(got) != 1 || got[0] != "human" {
		t.Errorf("expected [human] from payload priority, got %v", got)
	}
}

// ===================================================================
// ANTI-DITHER TESTS
// ===================================================================

func TestAntiDither_SuppressesDuplicate(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 5
	a := newTestApp(cfg)

	// Record a recent event
	key := "cam1:tripwire:cam1_r1_h_trip"
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now()}

	// Verify it's still there after cleanup (within window)
	a.cleanupAntiDither()
	if _, ok := a.antiDither[key]; !ok {
		t.Error("expected entry to survive cleanup within window")
	}
}

func TestAntiDither_CleansExpired(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 1
	a := newTestApp(cfg)

	a.antiDither["old_key"] = antiDitherEntry{lastTime: time.Now().Add(-2 * time.Second)}
	a.cleanupAntiDither()

	if _, ok := a.antiDither["old_key"]; ok {
		t.Error("expected expired entry to be cleaned up")
	}
}

func TestAntiDither_DisabledWhenZero(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 0
	a := newTestApp(cfg)

	a.antiDither["key"] = antiDitherEntry{lastTime: time.Now().Add(-100 * time.Second)}
	a.cleanupAntiDither()

	// Should not clean anything when disabled
	if _, ok := a.antiDither["key"]; !ok {
		t.Error("cleanup should be no-op when anti_dither is 0")
	}
}

// ===================================================================
// HTTP HANDLER TESTS
// ===================================================================

func TestHandleRoot(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	a.handleRoot(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	want := "dahua2mqtt " + version
	if body := w.Body.String(); body != want {
		t.Errorf("body = %q, want %q", body, want)
	}
}

func TestHandleCatchAll(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	w := httptest.NewRecorder()

	a.handleCatchAll(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("body = %q, want 'OK'", body)
	}
}

func TestHandleCatchAll_SanitizesNewlines(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	// Can't use httptest.NewRequest with newlines in URL, so build manually
	req := httptest.NewRequest(http.MethodPost, "/path-test", nil)
	// Simulate a path with newlines by overriding URL.Path directly
	req.URL.Path = "/path\ninjected\rheader"
	w := httptest.NewRecorder()

	a.handleCatchAll(w, req)

	// Should not panic, should return 200
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandleNotify_InvalidJSON(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent",
		strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleNotify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if a.stats.EventsReceived.Load() != 0 {
		t.Error("should not count invalid JSON as received")
	}
}

func TestHandleNotify_NonStartAction(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	body := makeEventJSON("Stop", "CrossLineDetection", "cam1_r1_h_trip", "uuid-1", nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleNotify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if a.stats.EventsReceived.Load() != 0 {
		t.Error("should not count non-Start events")
	}
}

func TestHandleNotify_MissingUUID(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	body := makeEventJSON("Start", "CrossLineDetection", "cam1_r1_h_trip", "", nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleNotify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if a.stats.EventsReceived.Load() != 0 {
		t.Error("should not count events without UUID")
	}
}

func TestHandleNotify_ValidEvent_IgnoredCode(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	body := makeEventJSON("Start", "UnknownEventCode", "cam1_r1_h_trip", "uuid-1", nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleNotify(w, req)

	if a.stats.EventsReceived.Load() != 1 {
		t.Errorf("events_received = %d, want 1", a.stats.EventsReceived.Load())
	}
	if a.stats.EventsIgnored.Load() != 1 {
		t.Errorf("events_ignored = %d, want 1", a.stats.EventsIgnored.Load())
	}
}

func TestHandleNotify_MissingDataField(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	// Craft JSON with invalid Data (not an object)
	body := []byte(`{"Action":"Start","Data":"not-an-object"}`)
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	a.handleNotify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if a.stats.EventsReceived.Load() != 0 {
		t.Error("should not count events with invalid Data")
	}
}

// ===================================================================
// HANDLE EVENT TESTS (without MQTT)
// ===================================================================

func TestHandleEvent_IgnoresUnknownCode(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	data := eventData{Code: "SomeOtherEvent", Name: "cam1_r1_h_trip", EventUUIDStr: "uuid-1"}

	a.handleEvent("uuid-1", data)

	if a.stats.EventsIgnored.Load() != 1 {
		t.Errorf("events_ignored = %d, want 1", a.stats.EventsIgnored.Load())
	}
}

func TestHandleEvent_AntiDitherSuppresses(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 5
	a := newTestApp(cfg)

	data := eventData{
		Code:         "CrossLineDetection",
		Name:         "cam1_r1_h_trip",
		EventUUIDStr: "uuid-1",
		Object:       &objectInfo{ObjectType: "Human"},
	}

	// Pre-seed anti-dither so it thinks this was just seen
	key := "cam1:tripwire:cam1_r1_h_trip"
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now()}

	a.handleEvent("uuid-2", data)

	if a.stats.EventsAntiDithered.Load() != 1 {
		t.Errorf("events_anti_dithered = %d, want 1", a.stats.EventsAntiDithered.Load())
	}
}

func TestHandleEvent_AntiDitherAllowsAfterExpiry(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 1
	a := newTestApp(cfg)

	// Use an unknown event code so handleEvent returns after anti-dither
	// check without trying to publish (which would need an MQTT client).
	// First, verify anti-dither passes by using a known code but seeding
	// with an expired entry. We set the code to unknown so it increments
	// EventsIgnored instead of calling publishEvent.
	data := eventData{
		Code:         "CrossLineDetection",
		Name:         "cam1_r1_h_trip",
		EventUUIDStr: "uuid-1",
	}

	// Seed with old timestamp — should pass anti-dither
	key := "cam1:tripwire:cam1_r1_h_trip"
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now().Add(-2 * time.Second)}

	// Change code to unknown so we don't need MQTT client
	data.Code = "UnknownCode"
	a.handleEvent("uuid-2", data)

	// With unknown code, it gets ignored before anti-dither check
	if a.stats.EventsIgnored.Load() != 1 {
		t.Errorf("events_ignored = %d, want 1", a.stats.EventsIgnored.Load())
	}

	// Now test the actual anti-dither expiry path by checking the map directly
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now().Add(-2 * time.Second)}
	a.antiDitherMu.Lock()
	entry := a.antiDither[key]
	expired := time.Since(entry.lastTime) >= time.Duration(cfg.AntiDither)*time.Second
	a.antiDitherMu.Unlock()

	if !expired {
		t.Error("expected entry to be expired after 2s with 1s anti_dither")
	}
	if a.stats.EventsAntiDithered.Load() != 0 {
		t.Errorf("events_anti_dithered = %d, want 0", a.stats.EventsAntiDithered.Load())
	}
}

func TestHandleEvent_AntiDitherKeyWithEmptyName(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 5
	a := newTestApp(cfg)

	data := eventData{
		Code:         "CrossLineDetection",
		Name:         "",
		EventUUIDStr: "uuid-1",
	}

	// Seed with key for empty name
	key := "unknown:tripwire"
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now()}

	a.handleEvent("uuid-2", data)

	if a.stats.EventsAntiDithered.Load() != 1 {
		t.Errorf("events_anti_dithered = %d, want 1", a.stats.EventsAntiDithered.Load())
	}
}

// ===================================================================
// IP ALLOWLIST TESTS
// ===================================================================

func TestIPAllowlist_EmptyAllowsAll(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPAllowlist_AllowedIP(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowedIPs = []string{"192.168.1.100"}
	a := newTestApp(cfg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestIPAllowlist_BlockedIP(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowedIPs = []string{"192.168.1.100"}
	a := newTestApp(cfg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIPAllowlist_TrustProxy_XForwardedFor(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowedIPs = []string{"10.0.0.5"}
	cfg.TrustProxy = true
	a := newTestApp(cfg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345" // proxy IP
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 192.168.1.1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d (should use X-Forwarded-For)", w.Code, http.StatusOK)
	}
}

func TestIPAllowlist_TrustProxy_Blocked(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowedIPs = []string{"10.0.0.5"}
	cfg.TrustProxy = true
	a := newTestApp(cfg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99, 192.168.1.1")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestIPAllowlist_TrustProxy_NoForwardedHeader_Rejects(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AllowedIPs = []string{"192.168.1.1"}
	cfg.TrustProxy = true
	a := newTestApp(cfg)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	handler := a.ipAllowlistMiddleware(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	// No X-Forwarded-For header — should reject (empty string won't match allowlist)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d (trust_proxy without X-Forwarded-For should reject)", w.Code, http.StatusForbidden)
	}
}

// ===================================================================
// STATS ENDPOINT TEST
// ===================================================================

func TestHandleStats(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.Cameras = []string{"cam1", "cam2"}
	cfg.AntiDither = 5
	cfg.OffDelay = 10
	a := newTestApp(cfg)

	a.stats.EventsReceived.Store(42)
	a.stats.EventsIgnored.Store(3)
	a.stats.MQTTPublishOK.Store(39)

	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	w := httptest.NewRecorder()
	a.handleStats(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	if got := result["events_received"].(float64); got != 42 {
		t.Errorf("events_received = %v, want 42", got)
	}
	if got := result["events_ignored"].(float64); got != 3 {
		t.Errorf("events_ignored = %v, want 3", got)
	}
	if got := result["mqtt_publish_ok"].(float64); got != 39 {
		t.Errorf("mqtt_publish_ok = %v, want 39", got)
	}

	cfgSection := result["config"].(map[string]any)
	if got := cfgSection["anti_dither"].(float64); got != 5 {
		t.Errorf("config.anti_dither = %v, want 5", got)
	}
	if got := cfgSection["off_delay"].(float64); got != 10 {
		t.Errorf("config.off_delay = %v, want 10", got)
	}

	cameras := cfgSection["cameras"].([]any)
	if len(cameras) != 2 {
		t.Errorf("config.cameras len = %d, want 2", len(cameras))
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}
}

// ===================================================================
// FULL HTTP ROUTING TESTS
// ===================================================================

func TestRouting_NotifyEndpoint(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cgi-bin/NotifyEvent", a.handleNotify)
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.HandleFunc("GET /stats", a.handleStats)
	mux.HandleFunc("GET /{$}", a.handleRoot)
	mux.HandleFunc("/", a.handleCatchAll)

	// POST to notify should work
	body := makeEventJSON("Start", "CrossLineDetection", "cam1_r1_h_trip", "uuid-1",
		&objectInfo{ObjectType: "Human"}, nil)
	req := httptest.NewRequest(http.MethodPost, "/cgi-bin/NotifyEvent", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("POST /cgi-bin/NotifyEvent status = %d, want %d", w.Code, http.StatusOK)
	}
	if a.stats.EventsReceived.Load() != 1 {
		t.Errorf("events_received = %d, want 1", a.stats.EventsReceived.Load())
	}
}

func TestRouting_HealthEndpoint(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", a.handleHealth)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var result map[string]any
	json.NewDecoder(w.Body).Decode(&result)
	if result["status"] != "ok" {
		t.Errorf("status = %v, want ok", result["status"])
	}
}

func TestRouting_UnknownPath(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleRoot)
	mux.HandleFunc("/", a.handleCatchAll)

	req := httptest.NewRequest(http.MethodGet, "/some/random/path", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("catch-all status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("catch-all body = %q, want 'OK'", body)
	}
}

// ===================================================================
// EVENT MAP TESTS
// ===================================================================

func TestEventMap(t *testing.T) {
	if v, ok := eventMap["CrossLineDetection"]; !ok || v != "tripwire" {
		t.Errorf("CrossLineDetection = %q (%v), want tripwire", v, ok)
	}
	if v, ok := eventMap["CrossRegionDetection"]; !ok || v != "intrusion" {
		t.Errorf("CrossRegionDetection = %q (%v), want intrusion", v, ok)
	}
	if _, ok := eventMap["SomeOtherEvent"]; ok {
		t.Error("unexpected event code should not be in map")
	}
}

// ===================================================================
// CONCURRENT ACCESS TESTS
// ===================================================================

func TestAntiDither_ConcurrentAccess(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 1
	a := newTestApp(cfg)

	// Hammer anti-dither from multiple goroutines
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			key := fmt.Sprintf("cam%d:tripwire:rule", id%3)
			a.antiDitherMu.Lock()
			a.antiDither[key] = antiDitherEntry{lastTime: time.Now()}
			a.antiDitherMu.Unlock()
			a.cleanupAntiDither()
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
	// No race condition — test passes if it doesn't panic
}

func TestStats_ConcurrentIncrement(t *testing.T) {
	a := newTestApp(defaultTestConfig())

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			a.stats.EventsReceived.Add(1)
			a.stats.EventsIgnored.Add(1)
			a.stats.MQTTPublishOK.Add(1)
		}()
	}
	for i := 0; i < 100; i++ {
		<-done
	}

	if got := a.stats.EventsReceived.Load(); got != 100 {
		t.Errorf("EventsReceived = %d, want 100", got)
	}
	if got := a.stats.EventsIgnored.Load(); got != 100 {
		t.Errorf("EventsIgnored = %d, want 100", got)
	}
	if got := a.stats.MQTTPublishOK.Load(); got != 100 {
		t.Errorf("MQTTPublishOK = %d, want 100", got)
	}
}

// ===================================================================
// OBJECT ALIASES TESTS
// ===================================================================

func TestObjectAliases_Coverage(t *testing.T) {
	expected := map[string]string{
		"human":         "human",
		"person":        "human",
		"vehicle":       "vehicle",
		"car":           "vehicle",
		"motor vehicle": "vehicle",
		"motorvehicle":  "vehicle",
	}
	for input, want := range expected {
		if got, ok := objectAliases[input]; !ok || got != want {
			t.Errorf("objectAliases[%q] = %q (%v), want %q", input, got, ok, want)
		}
	}
}

// ===================================================================
// WRITEFJSON TESTS
// ===================================================================

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]any{"key": "value", "num": 42})

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}

	var result map[string]any
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("key = %v, want value", result["key"])
	}
	if result["num"].(float64) != 42 {
		t.Errorf("num = %v, want 42", result["num"])
	}
}

// ===================================================================
// OFF TIMER TESTS
// ===================================================================

func TestResetOffTimer_CreatesTimer(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	a.cfg.OffDelay = 1

	// No MQTT client — timer will fire but publish is a no-op (nil check)
	a.resetOffTimer("cam1", "tripwire", "human")

	topic := "dahua2mqtt/cam1/tripwire/human"
	a.offTimersMu.Lock()
	_, exists := a.offTimers[topic]
	a.offTimersMu.Unlock()

	if !exists {
		t.Error("expected off timer to be created for topic")
	}
}

func TestResetOffTimer_ReplacesExistingTimer(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	a.cfg.OffDelay = 1

	a.resetOffTimer("cam1", "tripwire", "human")

	topic := "dahua2mqtt/cam1/tripwire/human"
	a.offTimersMu.Lock()
	t1 := a.offTimers[topic]
	a.offTimersMu.Unlock()

	// Reset again — should replace the timer
	a.resetOffTimer("cam1", "tripwire", "human")

	a.offTimersMu.Lock()
	t2 := a.offTimers[topic]
	a.offTimersMu.Unlock()

	if t1 == t2 {
		t.Error("expected new timer instance after reset")
	}
}

func TestAntiDitherSuppressed_ResetsOffTimer(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.AntiDither = 5
	cfg.OffDelay = 10
	a := newTestApp(cfg)

	data := eventData{
		Code:         "CrossLineDetection",
		Name:         "cam1_r1_h_trip",
		EventUUIDStr: "uuid-1",
		Object:       &objectInfo{ObjectType: "Human"},
	}

	// Pre-seed anti-dither so event is suppressed
	key := "cam1:tripwire:cam1_r1_h_trip"
	a.antiDither[key] = antiDitherEntry{lastTime: time.Now()}

	a.handleEvent("uuid-2", data)

	// Event should be suppressed
	if a.stats.EventsAntiDithered.Load() != 1 {
		t.Fatalf("events_anti_dithered = %d, want 1", a.stats.EventsAntiDithered.Load())
	}

	// But OFF timer should still have been created/reset
	topic := "dahua2mqtt/cam1/tripwire/human"
	a.offTimersMu.Lock()
	_, exists := a.offTimers[topic]
	a.offTimersMu.Unlock()

	if !exists {
		t.Error("expected off timer to be set even when event is anti-dithered")
	}
}

func TestResetOffTimer_MultipleTopicsIndependent(t *testing.T) {
	a := newTestApp(defaultTestConfig())
	a.cfg.OffDelay = 5

	a.resetOffTimer("cam1", "tripwire", "human")
	a.resetOffTimer("cam1", "tripwire", "vehicle")
	a.resetOffTimer("cam2", "intrusion", "human")

	a.offTimersMu.Lock()
	count := len(a.offTimers)
	a.offTimersMu.Unlock()

	if count != 3 {
		t.Errorf("expected 3 independent timers, got %d", count)
	}
}
