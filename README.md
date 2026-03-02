# dahua2mqtt

A lightweight Flask/Gunicorn bridge that receives IVS events from a Dahua NVR and publishes them to Home Assistant via MQTT.

Each camera automatically gets four HA binary sensors (via MQTT discovery):
**tripwire vehicle**, **tripwire human**, **intrusion vehicle**, **intrusion human**.

## Features

- **Event ingestion**: Receives Dahua IVS events (CrossLineDetection, CrossRegionDetection) over HTTP.
- **MQTT integration**: Publishes detection states and auto-registers HA binary sensors via MQTT discovery.
- **Auto-off**: Sensors reset to OFF after a configurable delay.
- **TTL-based cleanup**: Removes stale unmatched entries from memory.
- **Rotating logs**: Automatic log rotation (5x5 MB).
- **Anti-dither**: Optionally suppress repeated events per rule within a time window.
- **Monitoring endpoints**: `/health` and `/stats` for uptime and scraping.

## Architecture overview

```
Dahua NVR ──HTTP POST──▸ dahua2mqtt ──MQTT──▸ Home Assistant
                         (Flask)              (binary_sensor.*)
```

1. NVR sends an IVS event to `http://<bridge>:<port>/cgi-bin/NotifyEvent`.
2. The bridge extracts camera name, event type, and object class.
3. An MQTT message (`ON`) is published to the matching sensor topic.
4. HA picks it up via MQTT discovery; the sensor auto-resets after `off_delay` seconds.

## MQTT topics

| Purpose | Topic |
|---|---|
| Availability | `dahua2mqtt/status` |
| Sensor state | `dahua2mqtt/{camera}/{tripwire\|intrusion}/{vehicle\|human}` |
| HA discovery | `homeassistant/binary_sensor/dahua2mqtt_{camera}_{type}_{object}/config` |

## Configuration

The bridge loads `/etc/dahua2mqtt/config.yaml` (override with `CONFIG_FILE` env var).
See `config.example.yaml` for all options.

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

List every camera name prefix that appears in your IVS rule names.
Four binary sensors are created per camera.

### General

| Key | Env var | Default | Description |
|---|---|---|---|
| `port` | `PORT` | `8080` | HTTP listener port |
| `logfile` | `LOGFILE` | `/var/log/dahua2mqtt/dahua2mqtt.log` | Rotating log path |
| `log_level` | `LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `event_ttl` | `EVENT_TTL` | `120` | Drop unmatched events after N seconds |
| `anti_dither` | `ANTI_DITHER` | `0` | Suppress repeated events per rule within this window (0 = disabled) |
| `off_delay` | `OFF_DELAY` | `10` | Seconds before a binary sensor switches back to OFF |

## Object-type detection

The bridge determines whether a detection is **car** or **human** by:

1. Checking the event payload (`Data.Object.ObjectType`, `Data.Objects[].Type`, etc.).
2. Falling back to the IVS rule name convention:
   - `_c_` or segment `c` → vehicle
   - `_h_` or segment `h` → human
   - `_ch_` or segment `ch` → both
3. If neither yields a result, both vehicle and human sensors are triggered.

## NVR Configuration

On your NVR, under **Network → Alarm Center**:

1. Enable the `Enable` switch.
2. Set `Protocol Type` to `HTTP`.
3. Set `Server Address` to this bridge's IP (e.g. `192.168.1.10`).
4. Set `Port` to `8080` (or whatever you configured).
5. Hit `Apply`.

The NVR will send events to `http://<bridge>:<port>/cgi-bin/NotifyEvent`.

Then, for each rule under **Event → Alarm Center**:

1. Enable `Report Alarm`.
2. Set `Report Alarm` to `HTTP`.
3. Tick `Event`.

### IVS rule naming

Dahua NVR **does not send** channel IDs through the Alarm Center interface.
Use the rule name to encode camera identity and object type:

- `cam1_r1_h_trip` → camera 1, rule 1, human, tripwire
- `cam2_r1_ch_intrusion` → camera 2, rule 1, car + human, intrusion
- `cam1_r1_c_trip` → camera 1, rule 1, vehicle, tripwire

The first segment (before the first `_`) is used as the camera name and must match an entry in the `cameras` list.

## API Endpoints

### Health Check
```
GET /health
→ {"status": "ok", "pending_events": 0, "mqtt_connected": true}
```

### Statistics
```
GET /stats
→ {"events_received": 145, "mqtt_publish_ok": 140, ...}
```

## Installation

Install dependencies:
- `flask`, `gunicorn`, `paho-mqtt`, `pyyaml`

Create user, folders, permissions:

```bash
sudo groupadd --system dahua
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid dahua dahua
sudo mkdir -pv /opt/dahua2mqtt /etc/dahua2mqtt /var/log/dahua2mqtt
sudo chown -Rv dahua:dahua /opt/dahua2mqtt /etc/dahua2mqtt /var/log/dahua2mqtt
```

Copy files:

```bash
sudo cp dahua2mqtt.py /opt/dahua2mqtt/
sudo cp config.example.yaml /etc/dahua2mqtt/config.yaml   # edit before starting
sudo cp dahua2mqtt.service /etc/systemd/system/
```

Enable service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dahua2mqtt
sudo systemctl status dahua2mqtt
```

### LXC vs VM

A simple unprivileged Debian LXC (1 vCPU, 512 MB RAM, 4 GB disk) can handle 40+ events/sec.

## Security Notes

- Do NOT expose this bridge to the internet.
- Allow inbound traffic only from the Dahua camera VLAN.
- Allow outbound traffic only to your MQTT broker.

## License

MIT
