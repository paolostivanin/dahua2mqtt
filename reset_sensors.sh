#!/usr/bin/env bash
# Manage dahua2mqtt sensors on the MQTT broker.
#
# Usage:
#   ./reset_sensors.sh reset <broker> <cam1> [cam2 ...] [-u user] [-P pass]
#       Publish OFF (non-retained) to each sensor's state topic. Useful when
#       a sensor is stuck ON and you want HA to see OFF immediately.
#
#   ./reset_sensors.sh purge <broker> <cam1> [cam2 ...] [-u user] [-P pass]
#       Clear retained discovery + state topics for each given camera. Use
#       this AFTER removing a camera from config.yaml and restarting the
#       service, to remove its sensors from Home Assistant.

set -euo pipefail

usage() {
  echo "Usage: $0 reset|purge <broker> <cam...> [-u user] [-P pass]" >&2
  exit 1
}

MODE="${1:-}"
case "$MODE" in
  reset|purge) ;;
  *) usage ;;
esac
shift

BROKER="${1:-}"
[[ -n "$BROKER" ]] || usage
shift

CAMS=()
AUTH=()
while (( "$#" )); do
  case "$1" in
    -u) AUTH+=(-u "$2"); shift 2 ;;
    -P) AUTH+=(-P "$2"); shift 2 ;;
    *)  CAMS+=("$1");    shift   ;;
  esac
done

(( ${#CAMS[@]} )) || { echo "no cameras given" >&2; usage; }

for cam in "${CAMS[@]}"; do
  for type in tripwire intrusion; do
    for obj in human vehicle; do
      state="dahua2mqtt/$cam/$type/$obj"
      disc="homeassistant/binary_sensor/dahua2mqtt_${cam}_${type}_${obj}/config"
      if [[ "$MODE" == "purge" ]]; then
        mosquitto_pub -h "$BROKER" "${AUTH[@]}" -t "$state" -r -n
        mosquitto_pub -h "$BROKER" "${AUTH[@]}" -t "$disc"  -r -n
      else
        mosquitto_pub -h "$BROKER" "${AUTH[@]}" -t "$state" -m "OFF"
      fi
    done
  done
done

echo "$MODE complete for: ${CAMS[*]}"
