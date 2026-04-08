# Migration Guide: dahua-proxy (Python/webhook) → dahua2mqtt (Go/MQTT)

The old system (`dahua-proxy`) is a Python/Flask app served by Gunicorn that receives NVR events and forwards raw JSON to Home Assistant via an HTTP webhook. The new system (`dahua2mqtt`) is a single Go binary that receives the same NVR events but publishes structured ON/OFF states via MQTT with HA auto-discovery.

This is a complete rewrite with a different integration model — not a drop-in upgrade.

## Key differences

| | dahua-proxy (old) | dahua2mqtt (new) |
|--|-------------------|------------------|
| **Language** | Python 3 + Flask + Gunicorn | Go static binary |
| **HA integration** | HTTP webhook (`ha_webhook_url`) | MQTT discovery (binary sensors) |
| **HA config needed** | Webhook automation + template sensors | **None** — sensors auto-created |
| **Config path** | `/etc/dahua-proxy/config.yaml` | `/etc/dahua2mqtt/config.yaml` |
| **Install path** | `/opt/dahua-proxy/` | `/opt/dahua2mqtt/` |
| **Log path** | `/var/log/dahua-proxy/` | `/var/log/dahua2mqtt/` |
| **Service name** | `dahua-proxy.service` (gunicorn) | `dahua2mqtt.service` (binary) |
| **Dependencies** | Python, Flask, requests, pyyaml, gunicorn | **None** |
| **Object detection** | Not done — raw event forwarded | Extracts vehicle/human from payload or rule name |
| **Sensor OFF** | HA-side (manual or automation) | Server-side OFF timer (`off_delay`) |
| **Snapshots** | `snapshot_dir`, `snapshot_ttl`, `max_snapshot_size` | Not supported |
| **Event buffering** | `pending_events` dict + `event_ttl` | Stateless — processed immediately |
| **Anti-dither key** | `name or camera` (flat) | `camera:sensorType:name` (granular) |
| **IP allowlist** | Not supported | Optional (`allowed_ips`) |

## Pre-migration

### 1. Set up MQTT broker (if not already running)

dahua2mqtt requires an MQTT broker (Mosquitto, EMQX, etc.) that HA can connect to. If you already have MQTT in HA (for Zigbee2MQTT, etc.), you can reuse it.

### 2. Note your old config values

From `/etc/dahua-proxy/config.yaml`:
- `port` → reuse in new config
- `anti_dither` → reuse in new config
- `logfile` path and `log_level` → equivalent fields exist
- `ha_webhook_url`, `ha_timeout`, `ha_retries` → **removed** (MQTT replaces webhook)
- `snapshot_dir`, `snapshot_ttl`, `max_snapshot_size` → **removed** (not supported)
- `event_ttl` → **removed** (no event buffering)

### 3. Identify cameras

In the old system, camera names were extracted from events but not configured. In the new system, you must list them in `cameras:` so discovery can pre-register HA sensors. Camera names = first segment of your IVS rule names (e.g., rule `cam1_r1_h_trip` → camera `cam1`).

### 4. Document your HA webhook automations

You'll be removing the webhook trigger and any template sensors / automations built around the raw event JSON. The new MQTT sensors replace them with clean binary sensors per camera/event/object.

## Migration steps

### 1. Build the Go binary

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dahua2mqtt .
```

### 2. Create new directory structure

```bash
sudo mkdir -p /opt/dahua2mqtt
sudo mkdir -p /etc/dahua2mqtt
sudo mkdir -p /var/log/dahua2mqtt
sudo chown dahua:dahua /opt/dahua2mqtt /var/log/dahua2mqtt
```

### 3. Write the new config

Create `/etc/dahua2mqtt/config.yaml` (see `config.example.yaml`):

```yaml
mqtt:
  host: "BROKER_IP"
  port: 1883
  # username: ""
  # password: ""

cameras:
  - cam1
  - cam2

port: 8080                # same as old dahua-proxy
logfile: "/var/log/dahua2mqtt/dahua2mqtt.log"
log_level: "INFO"
anti_dither: 5            # carry over from old config
off_delay: 10             # seconds before sensor auto-OFF
```

Secure the config file (it may contain MQTT credentials):

```bash
sudo chown root:dahua /etc/dahua2mqtt/config.yaml
sudo chmod 640 /etc/dahua2mqtt/config.yaml
```

### 4. Deploy the binary

```bash
sudo cp dahua2mqtt /opt/dahua2mqtt/dahua2mqtt
sudo chmod 755 /opt/dahua2mqtt/dahua2mqtt
```

### 5. Install the systemd unit

```bash
sudo cp dahua2mqtt.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 6. Stop the old service

```bash
sudo systemctl stop dahua-proxy
sudo systemctl disable dahua-proxy
```

### 7. Start the new service

```bash
sudo systemctl enable --now dahua2mqtt
```

### 8. Verify

```bash
# Service running
sudo systemctl status dahua2mqtt
journalctl -u dahua2mqtt -f

# Health check
curl http://localhost:8080/health

# MQTT status topic
mosquitto_sub -h BROKER_IP -t "dahua2mqtt/#" -v
# Should see: dahua2mqtt/status online
# And discovery configs under homeassistant/binary_sensor/...
```

### 9. Verify HA sensors appear

In Home Assistant → Settings → Devices → search "Dahua". You should see one device per camera, each with 4 binary sensors (tripwire vehicle, tripwire human, intrusion vehicle, intrusion human).

### 10. Update NVR webhook target (if port changed)

If you kept the same port (8080) and host, the NVR needs no change — same endpoint: `POST /cgi-bin/NotifyEvent`. If the port changed, update the NVR's HTTP notification URL.

### 11. Clean up old HA webhook automations

The old webhook trigger and any template sensors parsing raw event JSON can be removed. The new MQTT binary sensors provide:

- `dahua2mqtt/{camera}/tripwire/vehicle` (ON/OFF)
- `dahua2mqtt/{camera}/tripwire/human` (ON/OFF)
- `dahua2mqtt/{camera}/intrusion/vehicle` (ON/OFF)
- `dahua2mqtt/{camera}/intrusion/human` (ON/OFF)

Update any automations to use these binary sensors as triggers instead of the webhook.

### 12. Clean up old installation (optional)

```bash
sudo rm -rf /opt/dahua-proxy
sudo rm /etc/systemd/system/dahua-proxy.service
sudo systemctl daemon-reload
# Keep old config/logs for a while in case of rollback:
# sudo rm -rf /etc/dahua-proxy /var/log/dahua-proxy
```

## Rollback

1. `sudo systemctl stop dahua2mqtt`
2. `sudo systemctl enable --now dahua-proxy`
3. If you changed the HTTP port, update the NVR's notification URL back to the old port
4. Re-enable HA webhook automations

## HA automation migration example

**Old** (webhook-based, required manual parsing):

```yaml
automation:
  trigger:
    - platform: webhook
      webhook_id: dahua_event
  action:
    # parse event_json, figure out camera/type, turn on input_boolean, etc.
```

**New** (MQTT binary sensors, zero config):

```yaml
automation:
  trigger:
    - platform: state
      entity_id: binary_sensor.dahua2mqtt_cam1_tripwire_human
      to: "on"
  action:
    # ...
```
