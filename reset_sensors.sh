#!/usr/bin/env bash
# Reset all dahua2mqtt sensors to OFF.
# Usage: ./reset_sensors.sh <broker> [user] [password]

BROKER="${1:?Usage: $0 <broker> [user] [password]}"
USER="$2"
PASS="$3"

AUTH=()
[[ -n "$USER" ]] && AUTH+=(-u "$USER")
[[ -n "$PASS" ]] && AUTH+=(-P "$PASS")

for cam in cam1 cam2 cam3 cam4 cam5 cam6; do
  for type in tripwire intrusion; do
    for obj in human vehicle; do
      mosquitto_pub -h "$BROKER" "${AUTH[@]}" -t "dahua2mqtt/$cam/$type/$obj" -m "OFF"
    done
  done
done

echo "All sensors reset to OFF."
