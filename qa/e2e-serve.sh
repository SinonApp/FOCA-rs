#!/bin/bash
# Controls the e2e harness (real core): qa/e2e-serve.sh start|stop|kill|restart|net-start|net-stop|status
#   E2E_DIR (default /tmp/foca-e2e): data/ is the data directory, net.json the "internet" config, pick/ the "phone files"
#   kill sends SIGKILL to foca serve (like Android killing the process: a running scan becomes stopped/restart on next start)
cd "$(dirname "$0")/.." || exit 2
ROOT=$(pwd)
E2E_DIR=${E2E_DIR:-/tmp/foca-e2e}
FOCA=${FOCA_BIN:-$ROOT/target/debug/foca}
PORT=${E2E_PORT:-8787}
NET_PORT=${E2E_NET_PORT:-8788}
mkdir -p "$E2E_DIR"
up() { for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$1/$2" && return 0; sleep 0.1; done; return 1; }
pidof_file() { [ -f "$E2E_DIR/$1.pid" ] && cat "$E2E_DIR/$1.pid"; }
case "$1" in
  net-start)
    "$FOCA" testnet --port "$NET_PORT" --corpus tests/corpus --domain "${E2E_DOMAIN:-example.test}" --delay-ms "${E2E_DELAY:-0}" \
      --write-config "$E2E_DIR/net.json" >> "$E2E_DIR/testnet.log" 2>&1 &
    echo $! > "$E2E_DIR/testnet.pid"; up "$NET_PORT" collinfo.json || { echo "testnet failed to start"; exit 1; } ;;
  net-stop) p=$(pidof_file testnet); [ -n "$p" ] && kill "$p" 2>/dev/null; rm -f "$E2E_DIR/testnet.pid" ;;
  start)
    "$FOCA" serve --data "$E2E_DIR/data" --port "$PORT" --ui "$ROOT/ui" --test-net "$E2E_DIR/net.json" --pick-dir "$E2E_DIR/pick" \
      >> "$E2E_DIR/serve.log" 2>&1 &
    echo $! > "$E2E_DIR/serve.pid"; up "$PORT" index.html || { echo "serve failed to start"; tail -5 "$E2E_DIR/serve.log"; exit 1; } ;;
  stop) p=$(pidof_file serve); [ -n "$p" ] && kill "$p" 2>/dev/null; sleep 0.3; rm -f "$E2E_DIR/serve.pid" ;;
  kill) p=$(pidof_file serve); [ -n "$p" ] && kill -9 "$p" 2>/dev/null; sleep 0.3; rm -f "$E2E_DIR/serve.pid" ;;
  restart) "$0" kill; "$0" start ;;
  delay) curl -s "http://127.0.0.1:$NET_PORT/__delay?ms=${2:-0}&cdx=${3:-0}"; echo ;;
  status) curl -s -X POST "http://127.0.0.1:$PORT/invoke" -d '{"cmd":"scan_status"}'; echo ;;
  *) echo "usage: $0 start|stop|kill|restart|net-start|net-stop|delay <ms> [cdx-ms]|status"; exit 2 ;;
esac
