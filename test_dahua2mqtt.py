"""Tests for dahua2mqtt."""

import json
import time
from unittest.mock import MagicMock, patch

import pytest

import dahua2mqtt


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset mutable state between tests."""
    dahua2mqtt.anti_dither_last.clear()
    for key in dahua2mqtt.stats:
        dahua2mqtt.stats[key] = 0
    yield


@pytest.fixture
def client():
    dahua2mqtt.app.config["TESTING"] = True
    with dahua2mqtt.app.test_client() as c:
        yield c


def _event(code="CrossLineDetection", name="cam1_r1_h_trip", uuid="test-uuid-1",
           action="Start", extra_data=None):
    """Build a valid Dahua event payload."""
    data = {"EventUUIDStr": uuid, "Code": code, "Name": name}
    if extra_data:
        data.update(extra_data)
    return {"Action": action, "Data": data}


# ===================================================================
# validate_event
# ===================================================================
class TestValidateEvent:
    def test_valid_event(self):
        ok, err = dahua2mqtt.validate_event(_event())
        assert ok is True
        assert err == ""

    def test_not_a_dict(self):
        ok, err = dahua2mqtt.validate_event("string")
        assert ok is False
        assert "JSON object" in err

    def test_wrong_action(self):
        ok, err = dahua2mqtt.validate_event(_event(action="Stop"))
        assert ok is False
        assert "START" in err

    def test_missing_data(self):
        ok, err = dahua2mqtt.validate_event({"Action": "Start"})
        assert ok is False
        assert "Data" in err

    def test_missing_uuid(self):
        ok, err = dahua2mqtt.validate_event(
            {"Action": "Start", "Data": {"Code": "X"}}
        )
        assert ok is False
        assert "EventUUIDStr" in err


# ===================================================================
# sanitize_mqtt
# ===================================================================
class TestSanitizeMqtt:
    def test_clean_value(self):
        assert dahua2mqtt.sanitize_mqtt("cam1") == "cam1"

    def test_strips_slash(self):
        assert dahua2mqtt.sanitize_mqtt("cam/1") == "cam1"

    def test_strips_plus(self):
        assert dahua2mqtt.sanitize_mqtt("cam+1") == "cam1"

    def test_strips_hash(self):
        assert dahua2mqtt.sanitize_mqtt("cam#1") == "cam1"

    def test_strips_null(self):
        assert dahua2mqtt.sanitize_mqtt("cam\x001") == "cam1"

    def test_strips_all(self):
        assert dahua2mqtt.sanitize_mqtt("/+#\x00evil/+#") == "evil"


# ===================================================================
# extract_camera
# ===================================================================
class TestExtractCamera:
    def test_normal_name(self):
        assert dahua2mqtt.extract_camera("cam1_r1_h_trip") == "cam1"

    def test_no_underscore(self):
        assert dahua2mqtt.extract_camera("cam1") == "cam1"

    def test_empty_string(self):
        assert dahua2mqtt.extract_camera("") == "unknown"

    def test_none(self):
        assert dahua2mqtt.extract_camera(None) == "unknown"

    def test_sanitizes_injection(self):
        assert dahua2mqtt.extract_camera("cam/1_rule") == "cam1"


# ===================================================================
# extract_object_types
# ===================================================================
class TestExtractObjectTypes:
    def test_from_object_field(self):
        data = {"Object": {"ObjectType": "Human"}}
        result = dahua2mqtt.extract_object_types(data, "cam1_r1")
        assert result == ["human"]

    def test_from_objects_array(self):
        data = {"Objects": [{"Type": "Car"}, {"Type": "Person"}]}
        result = dahua2mqtt.extract_object_types(data, "cam1_r1")
        assert set(result) == {"vehicle", "human"}

    def test_from_rule_name_human(self):
        result = dahua2mqtt.extract_object_types({}, "cam1_r1_h_trip")
        assert result == ["human"]

    def test_from_rule_name_vehicle(self):
        result = dahua2mqtt.extract_object_types({}, "cam1_r1_c_trip")
        assert result == ["vehicle"]

    def test_from_rule_name_both(self):
        result = dahua2mqtt.extract_object_types({}, "cam1_r1_ch_trip")
        assert set(result) == {"vehicle", "human"}

    def test_fallback_defaults_to_both(self):
        result = dahua2mqtt.extract_object_types({}, "cam1_r1_trip")
        assert set(result) == {"vehicle", "human"}

    def test_empty_name_defaults_to_both(self):
        result = dahua2mqtt.extract_object_types({}, "")
        assert set(result) == {"vehicle", "human"}

    def test_payload_takes_priority_over_name(self):
        data = {"Object": {"ObjectType": "Human"}}
        result = dahua2mqtt.extract_object_types(data, "cam1_r1_c_trip")
        assert result == ["human"]

    def test_motorvehicle_alias(self):
        data = {"Object": {"ObjectType": "MotorVehicle"}}
        result = dahua2mqtt.extract_object_types(data, "")
        assert result == ["vehicle"]


# ===================================================================
# handle_event
# ===================================================================
class TestHandleEvent:
    @patch.object(dahua2mqtt, "publish_event")
    def test_publishes_for_crossline(self, mock_pub):
        event = _event(code="CrossLineDetection", name="cam1_r1_h_trip")
        dahua2mqtt.handle_event("uuid-1", event)
        mock_pub.assert_called_once_with("cam1", "tripwire", "human")

    @patch.object(dahua2mqtt, "publish_event")
    def test_publishes_for_crossregion(self, mock_pub):
        event = _event(code="CrossRegionDetection", name="cam2_r1_c_intr")
        dahua2mqtt.handle_event("uuid-2", event)
        mock_pub.assert_called_once_with("cam2", "intrusion", "vehicle")

    @patch.object(dahua2mqtt, "publish_event")
    def test_ignores_unknown_code(self, mock_pub):
        event = _event(code="FaceDetection", name="cam1_r1_h")
        dahua2mqtt.handle_event("uuid-3", event)
        mock_pub.assert_not_called()
        assert dahua2mqtt.stats["events_ignored"] == 1

    @patch.object(dahua2mqtt, "publish_event")
    @patch.object(dahua2mqtt, "ANTI_DITHER", 5)
    def test_anti_dither_suppresses_duplicate(self, mock_pub):
        event = _event(code="CrossLineDetection", name="cam1_r1_h_trip")
        dahua2mqtt.handle_event("uuid-a", event)
        assert mock_pub.call_count == 1

        dahua2mqtt.handle_event("uuid-b", event)
        assert mock_pub.call_count == 1
        assert dahua2mqtt.stats["events_anti_dithered"] == 1

    @patch.object(dahua2mqtt, "publish_event")
    @patch.object(dahua2mqtt, "ANTI_DITHER", 5)
    def test_anti_dither_key_includes_sensor_type(self, mock_pub):
        """Different event codes on same camera should not collide."""
        ev1 = _event(code="CrossLineDetection", name="cam1_r1_h_trip")
        ev2 = _event(code="CrossRegionDetection", name="cam1_r1_h_intr")
        dahua2mqtt.handle_event("uuid-a", ev1)
        dahua2mqtt.handle_event("uuid-b", ev2)
        assert mock_pub.call_count == 2


# ===================================================================
# Flask routes
# ===================================================================
class TestNotifyRoute:
    @patch.object(dahua2mqtt, "handle_event")
    def test_valid_event_returns_200(self, mock_handle, client):
        resp = client.post(
            "/cgi-bin/NotifyEvent",
            data=json.dumps(_event()),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert dahua2mqtt.stats["events_received"] == 1
        mock_handle.assert_called_once()

    def test_invalid_event_returns_200(self, client):
        resp = client.post(
            "/cgi-bin/NotifyEvent",
            data=json.dumps({"Action": "Stop"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert dahua2mqtt.stats["events_received"] == 0

    def test_malformed_json_returns_200(self, client):
        resp = client.post(
            "/cgi-bin/NotifyEvent",
            data="not json at all",
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_empty_body_returns_200(self, client):
        resp = client.post("/cgi-bin/NotifyEvent")
        assert resp.status_code == 200


class TestHealthRoute:
    def test_returns_status_ok(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "mqtt_connected" in data
        assert "pending_events" not in data

    def test_returns_200(self, client):
        assert client.get("/health").status_code == 200


class TestStatsRoute:
    def test_returns_stats(self, client):
        resp = client.get("/stats")
        data = resp.get_json()
        assert "events_received" in data
        assert "uptime_seconds" in data
        assert "mqtt_connected" in data
        assert "pending_events" not in data
        assert "event_ttl" not in data.get("config", {})


class TestRootRoute:
    def test_alive(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"alive" in resp.data


class TestCatchAllRoutes:
    def test_catch_post(self, client):
        resp = client.post("/some/random/path")
        assert resp.status_code == 200

    def test_catch_get(self, client):
        resp = client.get("/some/random/path")
        assert resp.status_code == 200


# ===================================================================
# IP allowlist
# ===================================================================
class TestIPAllowlist:
    @patch.object(dahua2mqtt, "ALLOWED_IPS", {"192.168.1.100"})
    def test_allowed_ip_passes(self, client):
        resp = client.get("/health", headers={"X-Forwarded-For": "1.2.3.4"})
        # remote_addr in test client is 127.0.0.1
        # With TRUST_PROXY=False (default), it checks remote_addr
        # 127.0.0.1 not in allowlist → 403
        assert resp.status_code == 403

    @patch.object(dahua2mqtt, "ALLOWED_IPS", {"127.0.0.1"})
    def test_localhost_allowed(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    @patch.object(dahua2mqtt, "ALLOWED_IPS", {"10.0.0.1"})
    @patch.object(dahua2mqtt, "TRUST_PROXY", True)
    def test_trust_proxy_checks_xff(self, client):
        resp = client.get(
            "/health",
            headers={"X-Forwarded-For": "10.0.0.1, 192.168.1.1"},
        )
        assert resp.status_code == 200

    @patch.object(dahua2mqtt, "ALLOWED_IPS", {"10.0.0.1"})
    @patch.object(dahua2mqtt, "TRUST_PROXY", True)
    def test_trust_proxy_rejects_wrong_ip(self, client):
        resp = client.get(
            "/health",
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        assert resp.status_code == 403

    @patch.object(dahua2mqtt, "ALLOWED_IPS", set())
    def test_empty_allowlist_allows_all(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200


# ===================================================================
# cleanup_anti_dither
# ===================================================================
class TestCleanupAntiDither:
    @patch.object(dahua2mqtt, "ANTI_DITHER", 5)
    def test_removes_expired_entries(self):
        dahua2mqtt.anti_dither_last["old"] = time.time() - 10
        dahua2mqtt.anti_dither_last["fresh"] = time.time()
        dahua2mqtt.cleanup_anti_dither()
        assert "old" not in dahua2mqtt.anti_dither_last
        assert "fresh" in dahua2mqtt.anti_dither_last

    @patch.object(dahua2mqtt, "ANTI_DITHER", 0)
    def test_noop_when_disabled(self):
        dahua2mqtt.anti_dither_last["key"] = time.time() - 9999
        dahua2mqtt.cleanup_anti_dither()
        assert "key" in dahua2mqtt.anti_dither_last


# ===================================================================
# publish_event (MQTT interaction)
# ===================================================================
class TestPublishEvent:
    @patch.object(dahua2mqtt.mqtt_client, "publish")
    def test_success_increments_stat(self, mock_pub):
        mock_pub.return_value = MagicMock(rc=0)
        dahua2mqtt.publish_event("cam1", "tripwire", "human")
        mock_pub.assert_called_once_with("dahua2mqtt/cam1/tripwire/human", "ON")
        assert dahua2mqtt.stats["mqtt_publish_ok"] == 1

    @patch.object(dahua2mqtt.mqtt_client, "publish")
    def test_failure_increments_stat(self, mock_pub):
        mock_pub.return_value = MagicMock(rc=1)
        dahua2mqtt.publish_event("cam1", "tripwire", "human")
        assert dahua2mqtt.stats["mqtt_publish_fail"] == 1

    @patch.object(dahua2mqtt.mqtt_client, "publish")
    def test_sanitizes_topic_segments(self, mock_pub):
        mock_pub.return_value = MagicMock(rc=0)
        dahua2mqtt.publish_event("cam/1", "trip+wire", "hu#man")
        mock_pub.assert_called_once_with("dahua2mqtt/cam1/tripwire/human", "ON")
