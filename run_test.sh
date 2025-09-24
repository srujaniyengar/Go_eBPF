#!/bin/bash

# Usage:
#   ./run_test.sh pktblocker <interface> <port>
#   ./run_test.sh procfilter <interface> <process_name> <port>

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

if [ $# -lt 1 ]; then
  echo "Usage:"
  echo "  $0 pktblocker <interface> <port>"
  echo "  $0 procfilter <interface> <process_name> <port>"
  exit 1
fi

APP="$1"
shift

if [ "$APP" == "pktblocker" ]; then
  if [ $# -ne 2 ]; then
    echo "Usage: $0 pktblocker <interface> <port>"
    exit 1
  fi
  APP_PATH="apps/pktblocker/pktblocker"
  IFACE="$1"
  PORT="$2"
  if [ ! -f "$APP_PATH" ]; then
    echo "Building pktblocker..."
    (cd apps/pktblocker && go build -o pktblocker)
  fi
  echo "Running pktblocker on interface $IFACE to block port $PORT"
  "$APP_PATH" "$IFACE" "$PORT"

elif [ "$APP" == "procfilter" ]; then
  if [ $# -ne 3 ]; then
    echo "Usage: $0 procfilter <interface> <process_name> <port>"
    exit 1
  fi
  APP_PATH="apps/procfilter/procfilter"
  IFACE="$1"
  PROC="$2"
  PORT="$3"
  if [ ! -f "$APP_PATH" ]; then
    echo "Building procfilter..."
    (cd apps/procfilter && go build -o procfilter)
  fi
  echo "Running procfilter on interface $IFACE for process '$PROC' allowing port $PORT"
  "$APP_PATH" "$IFACE" "$PROC" "$PORT"

else
  echo "Unknown app: $APP"
  echo "Valid options: pktblocker, procfilter"
  exit 1
fi