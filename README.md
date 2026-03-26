# dahua2mqtt

A lightweight Go bridge that receives IVS events from a Dahua NVR over HTTP and publishes them to Home Assistant via MQTT discovery.

Each camera automatically gets four HA binary sensors:
**tripwire vehicle**, **tripwire human**, **intrusion vehicle**, **intrusion human**.

## Features

- **Single static binary** — no runtime dependencies, no Python, no pip. Just `scp` and run.
- **MQTT discovery** — binary sensors auto-register in HA on startup. No manual YAML sensor definitions needed.
- **Auto-off** — sensors reset to `OFF` after a configurable delay (`off_delay`), so HA dashboards show real-time detection state without manual reset.
- **Anti-dither** — suppress repeated events per camera/rule within a configurable time window to reduce notification noise.
- **Last Will & Testament** — HA marks sensors as `unavailable` if the bridge crashes or loses connection.
- **IP allowlist** — optionally restrict which IPs can send events (e.g., NVR VLAN only).
- **Rotating logs** — automatic log rotation (5 x 5 MB).
- **Monitoring** — `/health` and `/stats` endpoints for uptime and metrics.
- **Security hardened** — ships with a locked-down systemd unit (read-only filesystem, no capabilities, restricted syscalls).

## Architecture

```
Dahua NVR ──HTTP POST──> dahua2mqtt ──MQTT──> Home Assistant
                         (Go binary)          (binary_sensor.*)
```

1. NVR sends an IVS event to `http://<bridge>:<port>/cgi-bin/NotifyEvent`.
2. The bridge validates and extracts camera name, event type, and object class.
3. If anti-dither passes, an MQTT message (`ON`) is published to the matching sensor topic.
4. HA picks it up via MQTT discovery; the sensor auto-resets to `OFF` after `off_delay` seconds.

## MQTT topics

| Purpose | Topic |
|---|---|
| Availability (LWT) | `dahua2mqtt/status` (`online` / `offline`) |
| Sensor state | `dahua2mqtt/{camera}/{tripwire\|intrusion}/{vehicle\|human}` |
| HA discovery | `homeassistant/binary_sensor/dahua2mqtt_{camera}_{type}_{object}/config` |

## Requirements

- Go 1.24+ (build only — the compiled binary has no dependencies)

## Building

```bash
go build -o dahua2mqtt .
```

Cross-compile for a remote Linux server:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dahua2mqtt .
```

## Installation

Create user and directories:

```bash
sudo useradd -r -s /sbin/nologin dahua
sudo mkdir -p /opt/dahua2mqtt /etc/dahua2mqtt /var/log/dahua2mqtt
sudo chown dahua:dahua /var/log/dahua2mqtt
```

Deploy binary, config, and service:

```bash
sudo cp dahua2mqtt /opt/dahua2mqtt/
sudo chmod 755 /opt/dahua2mqtt/dahua2mqtt
sudo cp config.example.yaml /etc/dahua2mqtt/config.yaml  # edit before starting
sudo chown root:dahua /etc/dahua2mqtt/config.yaml
sudo chmod 640 /etc/dahua2mqtt/config.yaml
sudo cp dahua2mqtt.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dahua2mqtt
```

Verify:

```bash
curl http://localhost:8080/health
# {"mqtt_connected":true,"status":"ok"}

curl http://localhost:8080/stats
# {"version":"2.0.0","events_received":0,"mqtt_connected":true,...}
```

### Resource usage

A simple unprivileged LXC (1 vCPU, 64 MB RAM, 4 GB disk) is more than sufficient. The Go binary uses ~5-10 MB of memory at runtime.

## Configuration

The bridge reads `/etc/dahua2mqtt/config.yaml` by default (override with `CONFIG_FILE` env var). All keys can also be overridden via uppercase env vars.

See [`config.example.yaml`](config.example.yaml) for a complete example.

### MQTT

| Key | Env var | Default | Description |
|---|---|---|---|
| `mqtt.host` | `MQTT_HOST` | `localhost` | Broker hostname/IP |
| `mqtt.port` | `MQTT_PORT` | `1883` | Broker port |
| `mqtt.username` | `MQTT_USERNAME` | | Broker username |
| `mqtt.password` | `MQTT_PASSWORD` | | Broker password |

### Cameras

```yaml
cameras:
  - cam1
  - cam2
```

List every camera name prefix that appears in your IVS rule names. Four binary sensors are created per camera.

### General

| Key | Env var | Default | Description |
|---|---|---|---|
| `port` | `PORT` | `8080` | HTTP listener port |
| `logfile` | `LOGFILE` | `/var/log/dahua2mqtt/dahua2mqtt.log` | Rotating log path |
| `log_level` | `LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `anti_dither` | `ANTI_DITHER` | `0` | Suppress repeated events per camera/rule within N seconds (0 = disabled) |
| `off_delay` | `OFF_DELAY` | `10` | Seconds before a binary sensor auto-resets to `OFF` |

### Security

| Key | Env var | Default | Description |
|---|---|---|---|
| `allowed_ips` | | `[]` | IP allowlist (empty = allow all) |
| `trust_proxy` | `TRUST_PROXY` | `false` | Use `X-Forwarded-For` header for IP checks |

## Object-type detection

The bridge determines whether a detection is **vehicle** or **human** by:

1. Checking the event payload fields: `Data.Object.ObjectType`, `Data.Object.Type`, `Data.Objects[].ObjectType`, `Data.Objects[].Type`.
2. Falling back to the IVS rule name convention:
   - `_c_` or segment `c` → vehicle
   - `_h_` or segment `h` → human
   - `_ch_` or segment `ch` → both
3. If neither yields a result, both vehicle and human sensors are triggered.

Recognized aliases: `human`, `person` → human; `vehicle`, `car`, `motor vehicle`, `motorvehicle` → vehicle.

## NVR Configuration

On your NVR, under **Network → Alarm Center**:

1. Enable the checkbox.
2. Set `Protocol Type` to `HTTP`.
3. Set `Server Address` to this bridge's IP (e.g. `192.168.1.10`).
4. Set `Port` to `8080` (or whatever you configured).
5. Hit `Apply`.

Then, for each rule under **Event → Alarm Center**:

1. Enable `Report Alarm`.
2. Set `Report Alarm` to `HTTP`.
3. Tick `Event`.

### IVS rule naming

Dahua NVR **does not send** channel IDs through the Alarm Center interface. Use the rule name to encode camera identity and object type:

- `cam1_r1_h_trip` → camera 1, rule 1, human, tripwire
- `cam2_r1_ch_intrusion` → camera 2, rule 1, car + human, intrusion
- `cam1_r1_c_trip` → camera 1, rule 1, vehicle, tripwire

The first segment (before the first `_`) is used as the camera name and **must match** an entry in the `cameras` list.

## API Endpoints

### Health Check
```
GET /health
{"status": "ok", "mqtt_connected": true}
```

### Statistics
```
GET /stats
{
  "version": "2.0.0",
  "events_received": 145,
  "events_anti_dithered": 3,
  "events_ignored": 2,
  "mqtt_publish_ok": 140,
  "mqtt_publish_fail": 0,
  "mqtt_connected": true,
  "uptime_seconds": 3600,
  "uptime_formatted": "1h 0m",
  "config": {
    "anti_dither": 5,
    "off_delay": 10,
    "cameras": ["cam1", "cam2"]
  }
}
```

### Root
```
GET /
dahua2mqtt 2.0.0
```

## Security Notes

- Do NOT expose this bridge to the internet.
- Use `allowed_ips` to restrict to your NVR's IP.
- Allow outbound traffic only to your MQTT broker.
- The systemd unit enforces: read-only filesystem, no capabilities, restricted syscalls, no home directory access, private /tmp.

## License

MIT
