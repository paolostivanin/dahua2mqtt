package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"gopkg.in/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

// ===================================================================
// CONFIG
// ===================================================================

type mqttConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type config struct {
	MQTT       mqttConfig `yaml:"mqtt"`
	Cameras    []string   `yaml:"cameras"`
	Port       int        `yaml:"port"`
	Logfile    string     `yaml:"logfile"`
	LogLevel   string     `yaml:"log_level"`
	AllowedIPs []string   `yaml:"allowed_ips"`
	TrustProxy bool       `yaml:"trust_proxy"`
	AntiDither int        `yaml:"anti_dither"`
	OffDelay   int        `yaml:"off_delay"`
}

func loadConfig() config {
	path := envOr("CONFIG_FILE", "/etc/dahua2mqtt/config.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read config file %s: %v — using defaults\n", path, err)
		return defaultConfig()
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse config file %s: %v — using defaults\n", path, err)
		return defaultConfig()
	}

	applyDefaults(&cfg)
	applyEnvOverrides(&cfg)
	return cfg
}

func defaultConfig() config {
	return config{
		MQTT:     mqttConfig{Host: "localhost", Port: 1883},
		Port:     8080,
		Logfile:  "/var/log/dahua2mqtt/dahua2mqtt.log",
		LogLevel: "INFO",
		OffDelay: 10,
	}
}

func applyDefaults(cfg *config) {
	if cfg.MQTT.Host == "" {
		cfg.MQTT.Host = "localhost"
	}
	if cfg.MQTT.Port == 0 {
		cfg.MQTT.Port = 1883
	}
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	if cfg.Logfile == "" {
		cfg.Logfile = "/var/log/dahua2mqtt/dahua2mqtt.log"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "INFO"
	}
	if cfg.OffDelay == 0 {
		cfg.OffDelay = 10
	}
}

func applyEnvOverrides(cfg *config) {
	if v := os.Getenv("MQTT_HOST"); v != "" {
		cfg.MQTT.Host = v
	}
	if v := os.Getenv("MQTT_PORT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.MQTT.Port); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid MQTT_PORT %q, keeping %d\n", v, cfg.MQTT.Port)
		}
	}
	if v := os.Getenv("MQTT_USERNAME"); v != "" {
		cfg.MQTT.Username = v
	}
	if v := os.Getenv("MQTT_PASSWORD"); v != "" {
		cfg.MQTT.Password = v
	}
	if v := os.Getenv("LOGFILE"); v != "" {
		cfg.Logfile = v
	}
	if v := os.Getenv("PORT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.Port); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid PORT %q, keeping %d\n", v, cfg.Port)
		}
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("ANTI_DITHER"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.AntiDither); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid ANTI_DITHER %q, keeping %d\n", v, cfg.AntiDither)
		}
	}
	if v := os.Getenv("OFF_DELAY"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cfg.OffDelay); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: invalid OFF_DELAY %q, keeping %d\n", v, cfg.OffDelay)
		}
	}
	if v := os.Getenv("TRUST_PROXY"); v != "" {
		v = strings.ToLower(v)
		cfg.TrustProxy = v == "true" || v == "1" || v == "yes"
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ===================================================================
// CONSTANTS
// ===================================================================

const (
	version           = "2.0.0"
	topicPrefix       = "dahua2mqtt"
	haDiscoveryPrefix = "homeassistant"
)

var eventMap = map[string]string{
	"CrossLineDetection":   "tripwire",
	"CrossRegionDetection": "intrusion",
}

var objectAliases = map[string]string{
	"human":         "human",
	"person":        "human",
	"vehicle":       "vehicle",
	"car":           "vehicle",
	"motor vehicle": "vehicle",
	"motorvehicle":  "vehicle",
}

var objectTypes = []string{"vehicle", "human"}

// ===================================================================
// STATE
// ===================================================================

type stats struct {
	EventsReceived    atomic.Int64
	EventsAntiDithered atomic.Int64
	EventsIgnored     atomic.Int64
	MQTTPublishOK     atomic.Int64
	MQTTPublishFail   atomic.Int64
}

type antiDitherEntry struct {
	lastTime time.Time
}

type app struct {
	cfg        config
	mqttClient mqtt.Client
	stats      stats
	startTime  time.Time
	logger     *slog.Logger

	antiDither   map[string]antiDitherEntry
	antiDitherMu sync.Mutex

	offTimers   map[string]*time.Timer
	offTimerGen map[string]uint64
	offTimersMu sync.Mutex

	allowedIPs map[string]struct{}
}

// ===================================================================
// MQTT
// ===================================================================

func (a *app) setupMQTT() {
	broker := fmt.Sprintf("tcp://%s:%d", a.cfg.MQTT.Host, a.cfg.MQTT.Port)
	opts := mqtt.NewClientOptions().
		AddBroker(broker).
		SetClientID("dahua2mqtt").
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetWill(topicPrefix+"/status", "offline", 1, true).
		SetOnConnectHandler(a.onConnect).
		SetConnectionLostHandler(a.onDisconnect)

	if a.cfg.MQTT.Username != "" {
		opts.SetUsername(a.cfg.MQTT.Username)
		opts.SetPassword(a.cfg.MQTT.Password)
	}

	a.mqttClient = mqtt.NewClient(opts)
	token := a.mqttClient.Connect()
	go func() {
		token.Wait()
		if token.Error() != nil {
			a.logger.Error("MQTT initial connect failed", "error", token.Error())
		}
	}()
}

func (a *app) onConnect(_ mqtt.Client) {
	a.logger.Info("MQTT connected")
	a.mqttClient.Publish(topicPrefix+"/status", 1, true, "online")
	a.publishDiscovery()
}

func (a *app) onDisconnect(_ mqtt.Client, err error) {
	a.logger.Warn("MQTT disconnected", "error", err)
}

func (a *app) publishDiscovery() {
	count := 0
	for _, cam := range a.cfg.Cameras {
		for _, eventType := range []string{"tripwire", "intrusion"} {
			for _, objType := range objectTypes {
				sensorID := fmt.Sprintf("%s_%s_%s_%s", topicPrefix, cam, eventType, objType)
				stateTopic := fmt.Sprintf("%s/%s/%s/%s", topicPrefix, cam, eventType, objType)

				payload := map[string]any{
					"name":                  fmt.Sprintf("%s %s %s", cam, eventType, objType),
					"unique_id":             sensorID,
					"state_topic":           stateTopic,
					"payload_on":            "ON",
					"payload_off":           "OFF",
					"device_class":          "motion",
					"availability_topic":    topicPrefix + "/status",
					"payload_available":     "online",
					"payload_not_available": "offline",
					"device": map[string]any{
						"identifiers":  []string{fmt.Sprintf("%s_%s", topicPrefix, cam)},
						"name":         fmt.Sprintf("Dahua %s", cam),
						"manufacturer": "Dahua",
					},
				}

				data, _ := json.Marshal(payload)
				discoveryTopic := fmt.Sprintf("%s/binary_sensor/%s/config", haDiscoveryPrefix, sensorID)
				a.mqttClient.Publish(discoveryTopic, 1, true, data)
				count++
			}
		}
	}
	a.logger.Info("HA discovery published", "cameras", len(a.cfg.Cameras), "sensors", count)
}

func (a *app) publishEvent(camera, sensorType, objType string) {
	topic := fmt.Sprintf("%s/%s/%s/%s",
		topicPrefix,
		sanitizeMQTT(camera),
		sanitizeMQTT(sensorType),
		sanitizeMQTT(objType),
	)
	if a.mqttClient == nil {
		a.stats.MQTTPublishFail.Add(1)
		a.logger.Error("Publish failed: MQTT client not initialized", "topic", topic)
		return
	}
	token := a.mqttClient.Publish(topic, 0, false, "ON")
	if !token.WaitTimeout(5 * time.Second) {
		a.stats.MQTTPublishFail.Add(1)
		a.logger.Error("Publish timed out", "topic", topic)
	} else if token.Error() != nil {
		a.stats.MQTTPublishFail.Add(1)
		a.logger.Error("Publish failed", "topic", topic, "error", token.Error())
	} else {
		a.stats.MQTTPublishOK.Add(1)
		a.logger.Info("Published ON", "topic", topic)
	}
}

func (a *app) resetOffTimer(camera, sensorType, objType string) {
	topic := fmt.Sprintf("%s/%s/%s/%s",
		topicPrefix,
		sanitizeMQTT(camera),
		sanitizeMQTT(sensorType),
		sanitizeMQTT(objType),
	)
	duration := time.Duration(a.cfg.OffDelay) * time.Second

	a.offTimersMu.Lock()
	if t, ok := a.offTimers[topic]; ok {
		t.Stop()
	}
	a.offTimerGen[topic]++
	gen := a.offTimerGen[topic]
	a.offTimers[topic] = time.AfterFunc(duration, func() {
		a.offTimersMu.Lock()
		current := a.offTimerGen[topic]
		a.offTimersMu.Unlock()
		if current != gen {
			return // a newer timer superseded this one
		}
		if a.mqttClient == nil {
			return
		}
		token := a.mqttClient.Publish(topic, 0, false, "OFF")
		if !token.WaitTimeout(5 * time.Second) {
			a.logger.Error("Publish OFF timed out", "topic", topic)
		} else if token.Error() != nil {
			a.logger.Error("Publish OFF failed", "topic", topic, "error", token.Error())
		} else {
			a.logger.Info("Published OFF", "topic", topic)
		}
	})
	a.offTimersMu.Unlock()
}

// ===================================================================
// EVENT PROCESSING
// ===================================================================

// NVR event JSON structure.
type nvrEvent struct {
	Action string          `json:"Action"`
	Data   json.RawMessage `json:"Data"`
}

type eventData struct {
	Code         string         `json:"Code"`
	Name         string         `json:"Name"`
	EventUUIDStr string         `json:"EventUUIDStr"`
	Object       *objectInfo    `json:"Object"`
	Objects      []objectInfo   `json:"Objects"`
}

type objectInfo struct {
	ObjectType string `json:"ObjectType"`
	Type       string `json:"Type"`
}

func (a *app) handleEvent(uuid string, data eventData) {
	camera := extractCamera(data.Name)

	sensorType, ok := eventMap[data.Code]
	if !ok {
		a.stats.EventsIgnored.Add(1)
		a.logger.Debug("Ignoring event", "code", data.Code, "uuid", uuid)
		return
	}

	if a.cfg.AntiDither > 0 {
		ditherKey := fmt.Sprintf("%s:%s:%s", camera, sensorType, data.Name)
		if data.Name == "" {
			ditherKey = fmt.Sprintf("%s:%s", camera, sensorType)
		}

		a.antiDitherMu.Lock()
		entry, exists := a.antiDither[ditherKey]
		now := time.Now()
		if exists && now.Sub(entry.lastTime) < time.Duration(a.cfg.AntiDither)*time.Second {
			a.antiDitherMu.Unlock()
			a.stats.EventsAntiDithered.Add(1)
			a.logger.Info("Anti-dither suppressed", "uuid", uuid, "cam", camera, "type", sensorType)
			objTypes := extractObjectTypes(data, a.logger)
			for _, objType := range objTypes {
				a.resetOffTimer(camera, sensorType, objType)
			}
			return
		}
		a.antiDither[ditherKey] = antiDitherEntry{lastTime: now}
		a.antiDitherMu.Unlock()
	}

	objTypes := extractObjectTypes(data, a.logger)
	for _, objType := range objTypes {
		a.publishEvent(camera, sensorType, objType)
		a.resetOffTimer(camera, sensorType, objType)
	}
}

func extractCamera(name string) string {
	if name == "" {
		return "unknown"
	}
	parts := strings.SplitN(name, "_", 2)
	return sanitizeMQTT(parts[0])
}

func extractObjectTypes(data eventData, logger *slog.Logger) []string {
	types := make(map[string]struct{})

	// Try Data.Object.ObjectType / Data.Object.Type
	if data.Object != nil {
		for _, raw := range []string{data.Object.ObjectType, data.Object.Type} {
			if mapped, ok := objectAliases[strings.ToLower(raw)]; ok {
				types[mapped] = struct{}{}
			}
		}
	}

	// Try Data.Objects[].ObjectType / Data.Objects[].Type
	for _, item := range data.Objects {
		for _, raw := range []string{item.ObjectType, item.Type} {
			if mapped, ok := objectAliases[strings.ToLower(raw)]; ok {
				types[mapped] = struct{}{}
			}
		}
	}

	if len(types) > 0 {
		return mapKeys(types)
	}

	// Fallback: parse rule name segments
	parts := strings.Split(strings.ToLower(data.Name), "_")
	for _, part := range parts {
		if part == "ch" {
			return []string{"vehicle", "human"}
		}
		if part == "c" {
			types["vehicle"] = struct{}{}
		}
		if part == "h" {
			types["human"] = struct{}{}
		}
	}

	if len(types) == 0 {
		logger.Warn("No object type found in payload or rule name, defaulting to both", "name", data.Name)
		return []string{"vehicle", "human"}
	}
	return mapKeys(types)
}

func (a *app) cleanupAntiDither() {
	if a.cfg.AntiDither <= 0 {
		return
	}
	a.antiDitherMu.Lock()
	defer a.antiDitherMu.Unlock()
	cutoff := time.Now().Add(-time.Duration(a.cfg.AntiDither) * time.Second)
	for key, entry := range a.antiDither {
		if entry.lastTime.Before(cutoff) {
			delete(a.antiDither, key)
		}
	}
}

// ===================================================================
// HTTP HANDLERS
// ===================================================================

func (a *app) handleNotify(w http.ResponseWriter, r *http.Request) {
	a.cleanupAntiDither()

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var raw nvrEvent
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		a.logger.Warn("Invalid JSON", "error", err)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	if raw.Action != "Start" {
		a.logger.Warn("Not a START event", "action", raw.Action)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	var data eventData
	if err := json.Unmarshal(raw.Data, &data); err != nil {
		a.logger.Warn("Invalid Data field", "error", err)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	if data.EventUUIDStr == "" {
		a.logger.Warn("Missing EventUUIDStr")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	a.stats.EventsReceived.Add(1)
	camera := extractCamera(data.Name)
	a.logger.Info("Received START", "uuid", data.EventUUIDStr, "code", data.Code, "cam", camera)

	a.handleEvent(data.EventUUIDStr, data)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

func (a *app) mqttConnected() bool {
	if a.mqttClient == nil {
		return false
	}
	return a.mqttClient.IsConnected()
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	a.cleanupAntiDither()
	writeJSON(w, map[string]any{
		"status":         "ok",
		"mqtt_connected": a.mqttConnected(),
	})
}

func (a *app) handleStats(w http.ResponseWriter, _ *http.Request) {
	a.cleanupAntiDither()
	uptime := int(time.Since(a.startTime).Seconds())
	writeJSON(w, map[string]any{
		"version":              version,
		"events_received":      a.stats.EventsReceived.Load(),
		"events_anti_dithered": a.stats.EventsAntiDithered.Load(),
		"events_ignored":       a.stats.EventsIgnored.Load(),
		"mqtt_publish_ok":      a.stats.MQTTPublishOK.Load(),
		"mqtt_publish_fail":    a.stats.MQTTPublishFail.Load(),
		"mqtt_connected":       a.mqttConnected(),
		"uptime_seconds":       uptime,
		"uptime_formatted":     fmt.Sprintf("%dh %dm", uptime/3600, (uptime%3600)/60),
		"config": map[string]any{
			"anti_dither": a.cfg.AntiDither,
			"off_delay":   a.cfg.OffDelay,
			"cameras":     a.cfg.Cameras,
		},
	})
}

func (a *app) handleRoot(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintf(w, "dahua2mqtt %s", version)
}

func (a *app) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	safePath := strings.NewReplacer("\n", "", "\r", "").Replace(r.URL.Path)
	a.logger.Info("Unknown request", "method", r.Method, "path", safePath)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// ===================================================================
// IP ALLOWLIST MIDDLEWARE
// ===================================================================

func (a *app) ipAllowlistMiddleware(next http.Handler) http.Handler {
	if len(a.allowedIPs) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ip string
		if a.cfg.TrustProxy {
			forwarded := r.Header.Get("X-Forwarded-For")
			ip = strings.TrimSpace(strings.SplitN(forwarded, ",", 2)[0])
		} else {
			ip = r.RemoteAddr
			// Strip port
			if idx := strings.LastIndex(ip, ":"); idx != -1 {
				ip = ip[:idx]
			}
		}
		if _, ok := a.allowedIPs[ip]; !ok {
			a.logger.Warn("Rejected request", "ip", ip)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ===================================================================
// HELPERS
// ===================================================================

func sanitizeMQTT(value string) string {
	for _, ch := range []string{"/", "+", "#", "\x00"} {
		value = strings.ReplaceAll(value, ch, "")
	}
	return value
}

func mapKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func parseSlogLevel(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ===================================================================
// MAIN
// ===================================================================

func main() {
	showVersion := flag.Bool("v", false, "Print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `dahua2mqtt %s — Dahua NVR event bridge for Home Assistant via MQTT

Usage: dahua2mqtt [flags]

Flags:
  -v    Print version and exit
  -h    Show this help

Configuration:
  Reads %s (override with CONFIG_FILE env var).
  All config keys can also be set via uppercase env vars
  (MQTT_HOST, MQTT_PORT, PORT, LOG_LEVEL, etc).

Endpoints:
  POST /cgi-bin/NotifyEvent   Receive NVR events
  GET  /health                Health check
  GET  /stats                 Runtime statistics
`, version, envOr("CONFIG_FILE", "/etc/dahua2mqtt/config.yaml"))
	}
	flag.Parse()
	if *showVersion {
		fmt.Println("dahua2mqtt", version)
		os.Exit(0)
	}

	cfg := loadConfig()

	// Set up logging
	logWriter := &lumberjack.Logger{
		Filename:   cfg.Logfile,
		MaxSize:    5, // MB
		MaxBackups: 5,
	}

	level := parseSlogLevel(cfg.LogLevel)
	logger := slog.New(slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level}))

	// Build allowed IPs set
	allowedIPs := make(map[string]struct{}, len(cfg.AllowedIPs))
	for _, ip := range cfg.AllowedIPs {
		allowedIPs[ip] = struct{}{}
	}

	a := &app{
		cfg:        cfg,
		startTime:  time.Now(),
		logger:     logger,
		antiDither:  make(map[string]antiDitherEntry),
		offTimers:   make(map[string]*time.Timer),
		offTimerGen: make(map[string]uint64),
		allowedIPs: allowedIPs,
	}

	a.setupMQTT()

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cgi-bin/NotifyEvent", a.handleNotify)
	mux.HandleFunc("GET /health", a.handleHealth)
	mux.HandleFunc("GET /stats", a.handleStats)
	mux.HandleFunc("GET /{$}", a.handleRoot)
	mux.HandleFunc("/", a.handleCatchAll)

	handler := a.ipAllowlistMiddleware(mux)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		<-sigCh
		logger.Info("Graceful shutdown...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
		a.offTimersMu.Lock()
		for _, t := range a.offTimers {
			t.Stop()
		}
		a.offTimersMu.Unlock()
		token := a.mqttClient.Publish(topicPrefix+"/status", 1, true, "offline")
		token.WaitTimeout(5 * time.Second)
		a.mqttClient.Disconnect(1000)
		logger.Info("Final stats",
			"events_received", a.stats.EventsReceived.Load(),
			"events_anti_dithered", a.stats.EventsAntiDithered.Load(),
			"events_ignored", a.stats.EventsIgnored.Load(),
			"mqtt_publish_ok", a.stats.MQTTPublishOK.Load(),
			"mqtt_publish_fail", a.stats.MQTTPublishFail.Load(),
		)
	}()

	logger.Info("dahua2mqtt starting",
		"version", version,
		"port", cfg.Port,
		"mqtt", fmt.Sprintf("%s:%d", cfg.MQTT.Host, cfg.MQTT.Port),
		"cameras", cfg.Cameras,
		"anti_dither", cfg.AntiDither,
		"off_delay", cfg.OffDelay,
	)

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("HTTP server error", "error", err)
		os.Exit(1)
	}
}
