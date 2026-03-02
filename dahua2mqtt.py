#!/usr/bin/env python3
"""dahua2mqtt – Dahua NVR IVS event bridge to Home Assistant via MQTT."""

import json
import logging
import os
import signal
import sys
import time

import paho.mqtt.client as mqtt
import yaml
from flask import Flask, request
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# ===================================================================
# CONFIG
# ===================================================================
def load_config():
    path = os.getenv("CONFIG_FILE", "/etc/dahua2mqtt/config.yaml")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        print(f"Cannot read config file {path}: {e}")
        return {}

CFG = load_config()

def cfg(key, default):
    return os.getenv(key.upper(), CFG.get(key, default))

PORT = int(cfg("port", 8080))

LOGFILE = cfg("logfile", "/var/log/dahua2mqtt/dahua2mqtt.log")
LOG_LEVEL = cfg("log_level", "INFO").upper()

EVENT_TTL = int(cfg("event_ttl", 120))
ANTI_DITHER = int(cfg("anti_dither", 0))
OFF_DELAY = int(cfg("off_delay", 10))

CAMERAS = CFG.get("cameras", [])

mqtt_cfg = CFG.get("mqtt", {})
MQTT_HOST = os.getenv("MQTT_HOST", mqtt_cfg.get("host", "localhost"))
MQTT_PORT = int(os.getenv("MQTT_PORT", mqtt_cfg.get("port", 1883)))
MQTT_USER = os.getenv("MQTT_USERNAME", mqtt_cfg.get("username", ""))
MQTT_PASS = os.getenv("MQTT_PASSWORD", mqtt_cfg.get("password", ""))

TOPIC_PREFIX = "dahua2mqtt"
HA_DISCOVERY_PREFIX = "homeassistant"

# Dahua event code → sensor type
EVENT_MAP = {
    "CrossLineDetection": "tripwire",
    "CrossRegionDetection": "intrusion",
}

# Dahua object type → normalised label
OBJECT_ALIASES = {
    "human": "human",
    "person": "human",
    "vehicle": "vehicle",
    "car": "vehicle",
    "motor vehicle": "vehicle",
    "motorvehicle": "vehicle",
}

OBJECT_TYPES = ("vehicle", "human")

app_start_time = time.time()

# ===================================================================
# LOGGING
# ===================================================================
logger = logging.getLogger("dahua2mqtt")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

handler = RotatingFileHandler(LOGFILE, maxBytes=5_000_000, backupCount=5)
formatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ===================================================================
# INTERNAL STATE
# ===================================================================
pending_events: dict[str, tuple[float, dict]] = {}
anti_dither_last: dict[str, float] = {}

stats = {
    "events_received": 0,
    "events_dropped": 0,
    "events_anti_dithered": 0,
    "events_ignored": 0,
    "mqtt_publish_ok": 0,
    "mqtt_publish_fail": 0,
}

# ===================================================================
# MQTT CLIENT
# ===================================================================
mqtt_client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id="dahua2mqtt",
)


def publish_discovery():
    """Publish HA MQTT discovery configs for every camera × event × object."""
    for cam in CAMERAS:
        for event_type in ("tripwire", "intrusion"):
            for obj_type in OBJECT_TYPES:
                sensor_id = f"{TOPIC_PREFIX}_{cam}_{event_type}_{obj_type}"
                state_topic = f"{TOPIC_PREFIX}/{cam}/{event_type}/{obj_type}"

                payload = {
                    "name": f"{cam} {event_type} {obj_type}",
                    "unique_id": sensor_id,
                    "state_topic": state_topic,
                    "payload_on": "ON",
                    "payload_off": "OFF",
                    "off_delay": OFF_DELAY,
                    "device_class": "motion",
                    "availability_topic": f"{TOPIC_PREFIX}/status",
                    "payload_available": "online",
                    "payload_not_available": "offline",
                    "device": {
                        "identifiers": [f"{TOPIC_PREFIX}_{cam}"],
                        "name": f"Dahua {cam}",
                        "manufacturer": "Dahua",
                    },
                }

                discovery_topic = (
                    f"{HA_DISCOVERY_PREFIX}/binary_sensor/{sensor_id}/config"
                )
                mqtt_client.publish(
                    discovery_topic, json.dumps(payload), retain=True,
                )
                logger.debug(f"Discovery published: {discovery_topic}")

    logger.info(
        f"HA discovery published for {len(CAMERAS)} camera(s), "
        f"{len(CAMERAS) * 4} sensors"
    )


def on_connect(client, userdata, flags, reason_code, properties=None):
    logger.info(f"MQTT connected ({reason_code})")
    client.publish(f"{TOPIC_PREFIX}/status", "online", retain=True)
    publish_discovery()


def on_disconnect(client, userdata, flags, reason_code, properties=None):
    logger.warning(f"MQTT disconnected ({reason_code})")


mqtt_client.on_connect = on_connect
mqtt_client.on_disconnect = on_disconnect

# Last-will so HA marks sensors unavailable if the process dies
mqtt_client.will_set(f"{TOPIC_PREFIX}/status", "offline", retain=True)

if MQTT_USER:
    mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

mqtt_client.connect_async(MQTT_HOST, MQTT_PORT)
mqtt_client.loop_start()

# ===================================================================
# VALIDATION
# ===================================================================
def validate_event(raw: dict) -> tuple[bool, str]:
    if not isinstance(raw, dict):
        return False, "Not a JSON object"

    if raw.get("Action") != "Start":
        return False, "Not a START event"

    data = raw.get("Data")
    if not isinstance(data, dict):
        return False, "Missing Data field"

    if "EventUUIDStr" not in data:
        return False, "Missing EventUUIDStr"

    return True, ""


# ===================================================================
# CLEANUP STALE ENTRIES
# ===================================================================
def cleanup_pending():
    now = time.time()

    for uuid, (ts, _) in list(pending_events.items()):
        if now - ts > EVENT_TTL:
            pending_events.pop(uuid, None)
            stats["events_dropped"] += 1
            logger.info(f"Dropped stale event UUID={uuid} (> {EVENT_TTL}s)")

    if ANTI_DITHER > 0:
        for key, ts in list(anti_dither_last.items()):
            if now - ts > ANTI_DITHER:
                anti_dither_last.pop(key, None)


# ===================================================================
# OBJECT-TYPE EXTRACTION
# ===================================================================
def extract_object_types(data: dict, name: str) -> list[str]:
    """Return detected object types from event data, falling back to rule name."""
    types: set[str] = set()

    # Try Data.Object.ObjectType / Data.Object.Type
    obj = data.get("Object")
    if isinstance(obj, dict):
        for key in ("ObjectType", "Type"):
            mapped = OBJECT_ALIASES.get(obj.get(key, "").lower())
            if mapped:
                types.add(mapped)

    # Try Data.Objects[].ObjectType / Data.Objects[].Type
    for item in data.get("Objects", []):
        if isinstance(item, dict):
            for key in ("ObjectType", "Type"):
                mapped = OBJECT_ALIASES.get(item.get(key, "").lower())
                if mapped:
                    types.add(mapped)

    if types:
        return list(types)

    # Fallback: parse rule name segments
    # Convention: cam1_r1_{objects}_{type}_{severity}
    # objects: c = car, h = human, ch = both
    parts = name.lower().split("_") if name else []
    for part in parts:
        if part == "ch":
            return ["vehicle", "human"]
        if part == "c":
            types.add("vehicle")
        if part == "h":
            types.add("human")

    return list(types) if types else ["vehicle", "human"]


# ===================================================================
# CAMERA + EVENT HELPERS
# ===================================================================
def extract_camera(name: str) -> str:
    if not name:
        return "unknown"
    return name.split("_", 1)[0]


# ===================================================================
# PUBLISH TO MQTT
# ===================================================================
def publish_event(camera: str, sensor_type: str, obj_type: str):
    topic = f"{TOPIC_PREFIX}/{camera}/{sensor_type}/{obj_type}"
    result = mqtt_client.publish(topic, "ON")
    if result.rc == mqtt.MQTT_ERR_SUCCESS:
        stats["mqtt_publish_ok"] += 1
        logger.info(f"Published ON → {topic}")
    else:
        stats["mqtt_publish_fail"] += 1
        logger.error(f"Publish failed ({result.rc}) → {topic}")


# ===================================================================
# HANDLE EVENT
# ===================================================================
def handle_event(uuid: str, event_json: dict):
    data = event_json.get("Data", {})
    code = data.get("Code", "")
    name = data.get("Name", "")
    camera = extract_camera(name)

    sensor_type = EVENT_MAP.get(code)
    if sensor_type is None:
        stats["events_ignored"] += 1
        logger.debug(f"Ignoring event code={code} UUID={uuid}")
        return

    if ANTI_DITHER > 0:
        dither_key = name or camera
        last_ts = anti_dither_last.get(dither_key)
        if last_ts is not None and (time.time() - last_ts) < ANTI_DITHER:
            stats["events_anti_dithered"] += 1
            logger.info(
                f"Anti-dither suppressed UUID={uuid} cam={camera} "
                f"type={sensor_type}"
            )
            return
        anti_dither_last[dither_key] = time.time()

    obj_types = extract_object_types(data, name)
    for obj_type in obj_types:
        publish_event(camera, sensor_type, obj_type)


# ===================================================================
# FLASK ROUTES
# ===================================================================
@app.post("/cgi-bin/NotifyEvent")
def notify():
    cleanup_pending()

    raw = request.json or {}
    valid, err = validate_event(raw)
    if not valid:
        logger.warning(f"Invalid event: {err}")
        return "OK", 200

    data = raw.get("Data", {})
    uuid = data["EventUUIDStr"]

    pending_events[uuid] = (time.time(), raw)
    stats["events_received"] += 1

    code = data.get("Code", "unknown")
    camera = extract_camera(data.get("Name"))
    logger.info(f"Received START UUID={uuid} code={code} cam={camera}")

    handle_event(uuid, raw)

    return "OK", 200


@app.get("/health")
def health():
    cleanup_pending()
    return {
        "status": "ok",
        "pending_events": len(pending_events),
        "mqtt_connected": mqtt_client.is_connected(),
    }, 200


@app.get("/stats")
def stats_endpoint():
    cleanup_pending()
    uptime = int(time.time() - app_start_time)
    return {
        **stats,
        "pending_events": len(pending_events),
        "mqtt_connected": mqtt_client.is_connected(),
        "uptime_seconds": uptime,
        "uptime_formatted": f"{uptime // 3600}h {(uptime % 3600) // 60}m",
        "config": {
            "event_ttl": EVENT_TTL,
            "anti_dither": ANTI_DITHER,
            "off_delay": OFF_DELAY,
            "cameras": CAMERAS,
        },
    }, 200


@app.get("/")
def root():
    return "dahua2mqtt alive", 200


@app.post("/<path:subpath>")
def catch_post(subpath):
    logger.info(f"Unknown POST to /{subpath}")
    return "OK", 200


@app.get("/<path:subpath>")
def catch_get(subpath):
    logger.info(f"Unknown GET to /{subpath}")
    return "OK", 200


# ===================================================================
# SHUTDOWN
# ===================================================================
def signal_handler(sig, frame):
    logger.info("Graceful shutdown...")
    mqtt_client.publish(f"{TOPIC_PREFIX}/status", "offline", retain=True)
    mqtt_client.loop_stop()
    mqtt_client.disconnect()
    cleanup_pending()
    logger.info(f"Final stats: {stats}")
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# ===================================================================
# LOCAL DEV MODE
# ===================================================================
if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("dahua2mqtt starting in DEV mode")
    logger.info(f"LOG_LEVEL={LOG_LEVEL}")
    logger.info(f"MQTT={MQTT_HOST}:{MQTT_PORT}")
    logger.info(f"CAMERAS={CAMERAS}")
    logger.info("=" * 50)

    app.run(host="0.0.0.0", port=PORT, debug=True)
