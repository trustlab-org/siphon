#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p run logs state

pidfile=run/collector.pid
running() { [[ -f $pidfile ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; }

case "${1:-}" in
start)
  if running; then
    echo "collector already running (pid $(cat "$pidfile"))"
    exit 0
  fi
  [[ -r secrets/okta-key.pem ]] || { echo "missing secrets/okta-key.pem"; exit 1; }
  nohup ./bin/collector -e okta.env -c config/okta.yaml >>logs/collector.log 2>&1 &
  echo $! >"$pidfile"
  echo "started collector (pid $!)"
  ;;
stop)
  if running; then
    kill "$(cat "$pidfile")"
    echo "stopped collector"
  fi
  rm -f "$pidfile"
  ;;
status)
  if running; then echo "collector: running"; else echo "collector: stopped"; fi
  curl -s 127.0.0.1:4196/metrics | grep -E '^(collector_events_emitted|collector_poll_errors|collector_cursor_lag_seconds|collector_application_available|output_sent|output_error)' || echo "metrics unreachable"
  ;;
logs)
  tail -n "${2:-30}" logs/collector.log
  ;;
*)
  echo "usage: okta.sh start | stop | status | logs [lines]"
  exit 1
  ;;
esac
