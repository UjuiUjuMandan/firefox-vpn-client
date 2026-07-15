#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME="${SERVICE_NAME:-firefox-vpn-client}"
SERVICE_USER="${SERVICE_USER:-firefox-vpn}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"
STATE_DIR="${STATE_DIR:-/var/lib/$SERVICE_NAME}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/lib/$SERVICE_NAME}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/firefox-vpn-proxy}"
ENV_FILE="${ENV_FILE:-/etc/default/$SERVICE_NAME}"
UNIT_FILE="${UNIT_FILE:-/etc/systemd/system/$SERVICE_NAME.service}"
HEALTH_UNIT_FILE="${HEALTH_UNIT_FILE:-/etc/systemd/system/$SERVICE_NAME-health.service}"
HEALTH_TIMER_FILE="${HEALTH_TIMER_FILE:-/etc/systemd/system/$SERVICE_NAME-health.timer}"

CONFIG_KEYS=(
  LISTEN
  PROXY
  COUNTRY
  PROXY_STATE_FILE
  GUARDIAN
  TIMEOUT
  HANDSHAKE_TIMEOUT
  IDLE_TIMEOUT
  MAX_CONNS
  UPSTREAM_CONNS
  USE_H3
  VERIFY_EXIT
  EXIT_CHECK_URL
  EXIT_CHECK_TIMEOUT
  VERBOSE
  EXTRA_ARGS
  HEALTH_INTERVAL
  HEALTH_TIMEOUT
  HEALTH_VERBOSE
  HEALTH_TARGET
  HEALTH_TARGETS
  HEALTH_FAILURE_THRESHOLD
  HEALTH_FAILURE_STATE
  HEALTH_STATUS_GRACE
  STATUS_FILE
)

declare -A EXPLICIT_CONFIG
for key in "${CONFIG_KEYS[@]}"; do
  if [[ -v "$key" ]]; then
    EXPLICIT_CONFIG["$key"]="${!key}"
  fi
done

LISTEN="${LISTEN:-127.0.0.1:1080}"
PROXY="${PROXY:-}"
COUNTRY="${COUNTRY:-}"
PROXY_STATE_FILE="${PROXY_STATE_FILE:-$STATE_DIR/proxy-selection.json}"
GUARDIAN="${GUARDIAN:-}"
TIMEOUT="${TIMEOUT:-20s}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-10s}"
IDLE_TIMEOUT="${IDLE_TIMEOUT:-0}"
MAX_CONNS="${MAX_CONNS:-256}"
UPSTREAM_CONNS="${UPSTREAM_CONNS:-1}"
USE_H3="${USE_H3:-0}"
VERIFY_EXIT="${VERIFY_EXIT:-1}"
EXIT_CHECK_URL="${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
EXIT_CHECK_TIMEOUT="${EXIT_CHECK_TIMEOUT:-10s}"
VERBOSE="${VERBOSE:-0}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
HEALTH_INTERVAL="${HEALTH_INTERVAL:-30s}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-5}"
HEALTH_VERBOSE="${HEALTH_VERBOSE:-0}"
HEALTH_TARGET="${HEALTH_TARGET:-}"
HEALTH_TARGETS="${HEALTH_TARGETS:-}"
if [[ -z "$HEALTH_TARGETS" ]]; then
  if [[ -n "$HEALTH_TARGET" ]]; then
    HEALTH_TARGETS="$HEALTH_TARGET"
  else
    HEALTH_TARGETS="www.google.com:443,example.com:443"
  fi
fi
HEALTH_STATUS_GRACE="${HEALTH_STATUS_GRACE:-30}"
HEALTH_FAILURE_THRESHOLD="${HEALTH_FAILURE_THRESHOLD:-3}"
HEALTH_FAILURE_STATE="${HEALTH_FAILURE_STATE:-$STATE_DIR/health-failures}"
STATUS_FILE="${STATUS_FILE:-$STATE_DIR/status.json}"
PURGE="${PURGE:-0}"
SKIP_START="${SKIP_START:-0}"

ACTION="${1:-install}"

log() {
  printf '%s %s\n' "[$(date -Is)]" "$*"
}

die() {
  log "ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage:
  sudo ./scripts/install-systemd.sh install
  sudo ./scripts/install-systemd.sh login
  sudo ./scripts/install-systemd.sh install-login
  sudo ./scripts/install-systemd.sh health
  sudo ./scripts/install-systemd.sh status
  sudo ./scripts/install-systemd.sh restart
  sudo ./scripts/install-systemd.sh uninstall

Common environment overrides:
  SERVICE_NAME=$SERVICE_NAME
  SERVICE_USER=$SERVICE_USER
  STATE_DIR=$STATE_DIR
  BIN_PATH=$BIN_PATH
  LISTEN=$LISTEN
  PROXY=$PROXY
  COUNTRY=$COUNTRY
  PROXY_STATE_FILE=$PROXY_STATE_FILE
  TIMEOUT=$TIMEOUT
  HANDSHAKE_TIMEOUT=$HANDSHAKE_TIMEOUT
  IDLE_TIMEOUT=$IDLE_TIMEOUT
  MAX_CONNS=$MAX_CONNS
  UPSTREAM_CONNS=$UPSTREAM_CONNS
  USE_H3=$USE_H3
  VERIFY_EXIT=$VERIFY_EXIT
  EXIT_CHECK_URL=$EXIT_CHECK_URL
  EXIT_CHECK_TIMEOUT=$EXIT_CHECK_TIMEOUT
  VERBOSE=$VERBOSE
  HEALTH_INTERVAL=$HEALTH_INTERVAL
  HEALTH_TIMEOUT=$HEALTH_TIMEOUT
  HEALTH_VERBOSE=$HEALTH_VERBOSE
  HEALTH_TARGET=$HEALTH_TARGET
  HEALTH_TARGETS=$HEALTH_TARGETS
  HEALTH_FAILURE_THRESHOLD=$HEALTH_FAILURE_THRESHOLD
  HEALTH_FAILURE_STATE=$HEALTH_FAILURE_STATE
  HEALTH_STATUS_GRACE=$HEALTH_STATUS_GRACE
  STATUS_FILE=$STATUS_FILE
  EXTRA_ARGS="$EXTRA_ARGS"

Examples:
  sudo COUNTRY=US LISTEN=127.0.0.1:1088 ./scripts/install-systemd.sh install-login
  sudo USE_H3=1 VERBOSE=1 ./scripts/install-systemd.sh install
  sudo ./scripts/install-systemd.sh status
EOF
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "this action must run as root; retry with sudo"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

repo_root() {
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  cd -- "$script_dir/.." && pwd
}

single_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

write_env_var() {
  local key="$1"
  local value="$2"
  printf '%s=' "$key"
  single_quote "$value"
  printf '\n'
}

load_existing_env_file() {
  if [[ -r "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
  fi

  local key
  for key in "${!EXPLICIT_CONFIG[@]}"; do
    printf -v "$key" '%s' "${EXPLICIT_CONFIG[$key]}"
  done
}

service_shell() {
  if [[ -x /usr/sbin/nologin ]]; then
    printf '/usr/sbin/nologin'
  elif [[ -x /sbin/nologin ]]; then
    printf '/sbin/nologin'
  else
    printf '/bin/false'
  fi
}

ensure_service_user() {
  if getent passwd "$SERVICE_USER" >/dev/null; then
    return
  fi
  log "creating system user $SERVICE_USER"
  useradd \
    --system \
    --home-dir "$STATE_DIR" \
    --create-home \
    --shell "$(service_shell)" \
    "$SERVICE_USER"
}

resolve_service_group() {
  if ! getent group "$SERVICE_GROUP" >/dev/null; then
    SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
    log "using existing primary group $SERVICE_GROUP for $SERVICE_USER"
  fi
}

ensure_dirs() {
  install -d -m 0755 "$INSTALL_DIR"
  install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
}

build_binary() {
  need_cmd go
  local root
  root="$(repo_root)"
  log "building proxy binary from $root"
  (cd "$root" && go build -o "$BIN_PATH" ./cmd/proxy-demo)
  chmod 0755 "$BIN_PATH"
}

write_env_file() {
  log "writing $ENV_FILE"
  {
    printf '# Generated by scripts/install-systemd.sh. Edit values, then run: sudo systemctl restart %s\n' "$SERVICE_NAME"
    write_env_var SERVICE_NAME "$SERVICE_NAME"
    write_env_var BIN_PATH "$BIN_PATH"
    write_env_var LISTEN "$LISTEN"
    write_env_var PROXY "$PROXY"
    write_env_var COUNTRY "$COUNTRY"
    write_env_var PROXY_STATE_FILE "$PROXY_STATE_FILE"
    write_env_var GUARDIAN "$GUARDIAN"
    write_env_var TIMEOUT "$TIMEOUT"
    write_env_var HANDSHAKE_TIMEOUT "$HANDSHAKE_TIMEOUT"
    write_env_var IDLE_TIMEOUT "$IDLE_TIMEOUT"
    write_env_var MAX_CONNS "$MAX_CONNS"
    write_env_var UPSTREAM_CONNS "$UPSTREAM_CONNS"
    write_env_var USE_H3 "$USE_H3"
    write_env_var VERIFY_EXIT "$VERIFY_EXIT"
    write_env_var EXIT_CHECK_URL "$EXIT_CHECK_URL"
    write_env_var EXIT_CHECK_TIMEOUT "$EXIT_CHECK_TIMEOUT"
    write_env_var VERBOSE "$VERBOSE"
    write_env_var EXTRA_ARGS "$EXTRA_ARGS"
    write_env_var HEALTH_INTERVAL "$HEALTH_INTERVAL"
    write_env_var HEALTH_TIMEOUT "$HEALTH_TIMEOUT"
    write_env_var HEALTH_VERBOSE "$HEALTH_VERBOSE"
    write_env_var HEALTH_TARGET "$HEALTH_TARGET"
    write_env_var HEALTH_TARGETS "$HEALTH_TARGETS"
    write_env_var HEALTH_FAILURE_THRESHOLD "$HEALTH_FAILURE_THRESHOLD"
    write_env_var HEALTH_FAILURE_STATE "$HEALTH_FAILURE_STATE"
    write_env_var HEALTH_STATUS_GRACE "$HEALTH_STATUS_GRACE"
    write_env_var STATUS_FILE "$STATUS_FILE"
  } > "$ENV_FILE"
  chmod 0644 "$ENV_FILE"
}

write_run_script() {
  local run_script="$INSTALL_DIR/run.sh"
  log "writing $run_script"
  cat > "$run_script" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

ENV_FILE="${ENV_FILE:-/etc/default/${SERVICE_NAME:-firefox-vpn-client}}"
if [[ -r "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

BIN_PATH="${BIN_PATH:-/usr/local/bin/firefox-vpn-proxy}"
LISTEN="${LISTEN:-127.0.0.1:1080}"
TIMEOUT="${TIMEOUT:-20s}"
HANDSHAKE_TIMEOUT="${HANDSHAKE_TIMEOUT:-10s}"
MAX_CONNS="${MAX_CONNS:-256}"
UPSTREAM_CONNS="${UPSTREAM_CONNS:-1}"
IDLE_TIMEOUT="${IDLE_TIMEOUT:-0}"
STATUS_FILE="${STATUS_FILE:-}"
PROXY_STATE_FILE="${PROXY_STATE_FILE:-}"
COUNTRY="${COUNTRY:-}"
VERIFY_EXIT="${VERIFY_EXIT:-1}"
EXIT_CHECK_URL="${EXIT_CHECK_URL:-https://www.cloudflare.com/cdn-cgi/trace}"
EXIT_CHECK_TIMEOUT="${EXIT_CHECK_TIMEOUT:-10s}"

args=(-listen "$LISTEN" -timeout "$TIMEOUT" -handshake-timeout "$HANDSHAKE_TIMEOUT" -idle-timeout "$IDLE_TIMEOUT" -max-conns "$MAX_CONNS" -upstream-conns "$UPSTREAM_CONNS" -status-file "$STATUS_FILE" -proxy-state-file "$PROXY_STATE_FILE" -verify-exit="$VERIFY_EXIT" -exit-check-url "$EXIT_CHECK_URL" -exit-check-timeout "$EXIT_CHECK_TIMEOUT")

if [[ -n "${PROXY:-}" ]]; then
  args+=(-proxy "$PROXY")
elif [[ -n "$COUNTRY" ]]; then
  args+=(-country "$COUNTRY")
fi
if [[ -n "${GUARDIAN:-}" ]]; then
  args+=(-guardian "$GUARDIAN")
fi
if [[ "${USE_H3:-0}" == "1" || "${USE_H3:-0}" == "true" ]]; then
  args+=(-h3)
fi
if [[ "${VERBOSE:-0}" == "1" || "${VERBOSE:-0}" == "true" ]]; then
  args+=(-verbose)
fi
if [[ -n "${EXTRA_ARGS:-}" ]]; then
  # EXTRA_ARGS is intentionally whitespace-split for advanced flags.
  # Keep secrets out of this file.
  read -r -a extra_args <<< "$EXTRA_ARGS"
  args+=("${extra_args[@]}")
fi

exec "$BIN_PATH" "${args[@]}"
EOF
  chmod 0755 "$run_script"
}

write_healthcheck_script() {
  local health_script="$INSTALL_DIR/healthcheck.sh"
  log "writing $health_script"
  cat > "$health_script" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME="${SERVICE_NAME:-firefox-vpn-client}"
ENV_FILE="${ENV_FILE:-/etc/default/$SERVICE_NAME}"
if [[ -r "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

LISTEN="${LISTEN:-127.0.0.1:1080}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-5}"
HEALTH_VERBOSE="${HEALTH_VERBOSE:-0}"
STATUS_FILE="${STATUS_FILE:-}"
HEALTH_STATUS_GRACE="${HEALTH_STATUS_GRACE:-30}"
HEALTH_FAILURE_THRESHOLD="${HEALTH_FAILURE_THRESHOLD:-3}"
HEALTH_FAILURE_STATE="${HEALTH_FAILURE_STATE:-/var/lib/$SERVICE_NAME/health-failures}"
HEALTH_TARGETS="${HEALTH_TARGETS:-}"
if [[ -z "$HEALTH_TARGETS" ]]; then
  if [[ -n "${HEALTH_TARGET:-}" ]]; then
    HEALTH_TARGETS="$HEALTH_TARGET"
  else
    HEALTH_TARGETS="www.google.com:443,example.com:443"
  fi
fi

log() {
  printf '%s %-5s %s\n' "$(date -Is)" "$1" "$2"
}

restart_service() {
  log WARN "restarting $SERVICE_NAME"
  systemctl reset-failed "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE_NAME.service"
}

fail() {
  log ERROR "$1"
  restart_service
  exit 1
}

record_data_failure() {
  local message="$1"
  local count=0
  if [[ -r "$HEALTH_FAILURE_STATE" ]]; then
    read -r count < "$HEALTH_FAILURE_STATE" || count=0
  fi
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  [[ "$HEALTH_FAILURE_THRESHOLD" =~ ^[1-9][0-9]*$ ]] || HEALTH_FAILURE_THRESHOLD=3
  count=$((count + 1))
  mkdir -p "$(dirname -- "$HEALTH_FAILURE_STATE")"
  printf '%s\n' "$count" > "$HEALTH_FAILURE_STATE"
  if (( count < HEALTH_FAILURE_THRESHOLD )); then
    log WARN "$message; consecutive_failures=$count threshold=$HEALTH_FAILURE_THRESHOLD"
    exit 0
  fi
  rm -f "$HEALTH_FAILURE_STATE"
  fail "$message; consecutive_failures=$count threshold=$HEALTH_FAILURE_THRESHOLD"
}

clear_data_failures() {
  rm -f "$HEALTH_FAILURE_STATE"
}

parse_listen() {
  local value="$1"
  HEALTH_HOST=""
  HEALTH_PORT=""

  if [[ "$value" =~ ^\[(.*)\]:(.*)$ ]]; then
    HEALTH_HOST="${BASH_REMATCH[1]}"
    HEALTH_PORT="${BASH_REMATCH[2]}"
  elif [[ "$value" == :* ]]; then
    HEALTH_HOST="127.0.0.1"
    HEALTH_PORT="${value#:}"
  else
    HEALTH_HOST="${value%:*}"
    HEALTH_PORT="${value##*:}"
  fi

  if [[ -z "$HEALTH_HOST" || "$HEALTH_HOST" == "$HEALTH_PORT" || "$HEALTH_HOST" == "0.0.0.0" || "$HEALTH_HOST" == "::" ]]; then
    HEALTH_HOST="127.0.0.1"
  fi
}

check_socks_with_python() {
  local target="$1"
  python3 - "$HEALTH_HOST" "$HEALTH_PORT" "$HEALTH_TIMEOUT" "$target" <<'PY'
import ipaddress
import socket
import ssl
import sys

proxy_host, proxy_port, timeout, target = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]

def split_host_port(value):
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or len(value) <= end + 2 or value[end + 1] != ":":
            raise SystemExit(f"invalid target: {value!r}")
        return value[1:end], int(value[end + 2:])
    host, sep, port = value.rpartition(":")
    if not sep or not host:
        raise SystemExit(f"invalid target: {value!r}")
    return host, int(port)

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise SystemExit("unexpected EOF from SOCKS5 proxy")
        data += chunk
    return data

def socks_addr(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if len(encoded) > 255:
            raise SystemExit("target host is too long for SOCKS5")
        return b"\x03" + bytes([len(encoded)]) + encoded
    if ip.version == 4:
        return b"\x01" + ip.packed
    return b"\x04" + ip.packed

target_host, target_port = split_host_port(target)
if not 0 < target_port <= 65535:
    raise SystemExit(f"invalid target port: {target_port}")

with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")
    data = recv_exact(sock, 2)
    if data != b"\x05\x00":
        raise SystemExit(f"unexpected SOCKS5 greeting response: {data!r}")
    request = b"\x05\x01\x00" + socks_addr(target_host) + target_port.to_bytes(2, "big")
    sock.sendall(request)
    header = recv_exact(sock, 4)
    if header[0] != 5:
        raise SystemExit(f"unexpected SOCKS5 reply version: {header[0]}")
    if header[1] != 0:
        raise SystemExit(f"SOCKS5 CONNECT failed with reply code {header[1]}")
    atyp = header[3]
    if atyp == 1:
        recv_exact(sock, 4)
    elif atyp == 3:
        recv_exact(sock, recv_exact(sock, 1)[0])
    elif atyp == 4:
        recv_exact(sock, 16)
    else:
        raise SystemExit(f"unexpected SOCKS5 reply address type: {atyp}")
    recv_exact(sock, 2)

    try:
        ipaddress.ip_address(target_host)
        target_is_ip = True
    except ValueError:
        target_is_ip = False

    if target_port == 443 and not target_is_ip:
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=target_host) as tls_sock:
            tls_sock.settimeout(timeout)
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {target_host}\r\n"
                "Connection: close\r\nUser-Agent: firefox-vpn-healthcheck\r\n\r\n"
            ).encode("ascii")
            tls_sock.sendall(request)
            if not tls_sock.recv(1):
                raise SystemExit("unexpected EOF during HTTPS data probe")
PY
}

check_status_with_python() {
  [[ -r "$STATUS_FILE" ]] || return 1
  python3 - "$STATUS_FILE" "$HEALTH_STATUS_GRACE" <<'PY'
import json
import sys
from datetime import datetime, timedelta, timezone

status_file = sys.argv[1]
grace = int(sys.argv[2])

with open(status_file, "r", encoding="utf-8") as fh:
    status = json.load(fh)

expiry_text = status.get("proxy_pass_expires_at")
if not expiry_text:
    raise SystemExit("missing proxy_pass_expires_at in status file")

expiry = datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
now = datetime.now(timezone.utc)
if expiry.tzinfo is None:
    expiry = expiry.replace(tzinfo=timezone.utc)
if now > expiry + timedelta(seconds=grace):
    raise SystemExit(f"proxy pass expired at {expiry.isoformat()}")
PY
}

check_tcp_with_bash() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${HEALTH_TIMEOUT}s" bash -c ':</dev/tcp/$1/$2' bash "$HEALTH_HOST" "$HEALTH_PORT"
  else
    bash -c ':</dev/tcp/$1/$2' bash "$HEALTH_HOST" "$HEALTH_PORT"
  fi
}

service_state="$(systemctl is-active "$SERVICE_NAME.service" || true)"
case "$service_state" in
  active)
    ;;
  inactive)
    log INFO "$SERVICE_NAME.service is inactive; assuming it was stopped intentionally"
    exit 0
    ;;
  activating|reloading|deactivating)
    log INFO "$SERVICE_NAME.service is $service_state; deferring health check"
    exit 0
    ;;
  *)
    fail "$SERVICE_NAME.service is $service_state"
    ;;
esac

parse_listen "$LISTEN"
if [[ -z "$HEALTH_PORT" || ! "$HEALTH_PORT" =~ ^[0-9]+$ ]]; then
  fail "could not parse LISTEN=$LISTEN"
fi

if command -v python3 >/dev/null 2>&1; then
  if [[ -n "$STATUS_FILE" ]]; then
    check_status_with_python || fail "status file is stale or unreadable: $STATUS_FILE"
  fi
  IFS=',' read -r -a HEALTH_TARGET_LIST <<< "$HEALTH_TARGETS"
  health_success=0
  health_failure=0
  failed_targets=""
  for target in "${HEALTH_TARGET_LIST[@]}"; do
    target="${target#"${target%%[![:space:]]*}"}"
    target="${target%"${target##*[![:space:]]}"}"
    [[ -n "$target" ]] || continue
    if check_socks_with_python "$target"; then
      health_success=$((health_success + 1))
    else
      health_failure=$((health_failure + 1))
      failed_targets="${failed_targets:+$failed_targets,}$target"
      log WARN "SOCKS5 data health check failed at $HEALTH_HOST:$HEALTH_PORT target=$target"
    fi
  done
  if (( health_success == 0 )); then
    record_data_failure "all SOCKS5 data health checks failed at $HEALTH_HOST:$HEALTH_PORT targets=$failed_targets"
  fi
  clear_data_failures
  if (( health_failure > 0 )); then
    log WARN "SOCKS5 proxy remains healthy because $health_success target(s) succeeded; failed=$failed_targets"
  fi
else
  if [[ "$HEALTH_VERBOSE" == "1" || "$HEALTH_VERBOSE" == "true" ]]; then
    log WARN "python3 missing; falling back to local TCP health check without upstream CONNECT"
  fi
  check_tcp_with_bash || fail "TCP health check failed at $HEALTH_HOST:$HEALTH_PORT"
fi

if [[ "$HEALTH_VERBOSE" == "1" || "$HEALTH_VERBOSE" == "true" ]]; then
  log INFO "$SERVICE_NAME healthy at $HEALTH_HOST:$HEALTH_PORT targets=$HEALTH_TARGETS"
fi
EOF
  chmod 0755 "$health_script"
}

write_units() {
  log "writing $UNIT_FILE"
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Firefox VPN SOCKS5 proxy
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=40

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$STATE_DIR
Environment=HOME=$STATE_DIR
Environment=SERVICE_NAME=$SERVICE_NAME
Environment=ENV_FILE=$ENV_FILE
EnvironmentFile=-$ENV_FILE
ExecStart=$INSTALL_DIR/run.sh
Restart=always
RestartSec=10s
TimeoutStopSec=20s
KillSignal=SIGINT
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$STATE_DIR
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  log "writing $HEALTH_UNIT_FILE"
  cat > "$HEALTH_UNIT_FILE" <<EOF
[Unit]
Description=Health check for Firefox VPN SOCKS5 proxy
After=$SERVICE_NAME.service

[Service]
Type=oneshot
Environment=SERVICE_NAME=$SERVICE_NAME
Environment=ENV_FILE=$ENV_FILE
ExecStart=$INSTALL_DIR/healthcheck.sh
EOF

  log "writing $HEALTH_TIMER_FILE"
  cat > "$HEALTH_TIMER_FILE" <<EOF
[Unit]
Description=Run Firefox VPN SOCKS5 proxy health check

[Timer]
OnBootSec=$HEALTH_INTERVAL
OnUnitActiveSec=$HEALTH_INTERVAL
AccuracySec=5s
Unit=$SERVICE_NAME-health.service

[Install]
WantedBy=timers.target
EOF
}

token_file() {
  printf '%s/.firefox-vpn-tokens.json' "$STATE_DIR"
}

has_tokens() {
  [[ -s "$(token_file)" ]]
}

has_location_selection() {
  [[ -n "$PROXY" || -n "$COUNTRY" || -s "$PROXY_STATE_FILE" ]]
}

require_location_selection() {
  [[ -z "$PROXY" || -z "$COUNTRY" ]] || die "PROXY and COUNTRY are mutually exclusive; configure only one"
  has_location_selection || die "no VPN location configured; set COUNTRY=US (or another country code) or PROXY=HOST:PORT before starting the service"
}

daemon_reload() {
  systemctl daemon-reload
}

enable_and_start() {
  systemctl enable --now "$SERVICE_NAME.service"
  systemctl enable --now "$SERVICE_NAME-health.timer"
}

install_all() {
  need_root
  need_cmd systemctl
  need_cmd useradd
  need_cmd getent
  ensure_service_user
  resolve_service_group
  ensure_dirs
  load_existing_env_file
  build_binary
  write_env_file
  write_run_script
  write_healthcheck_script
  write_units
  daemon_reload

  if [[ "$SKIP_START" == "1" ]]; then
    log "installed but start skipped by SKIP_START=1"
  elif has_tokens; then
    require_location_selection
    log "token file exists; enabling and starting service"
    enable_and_start
  else
    log "installed but not started: token file is missing at $(token_file)"
    log "run: sudo COUNTRY=US $0 login"
  fi
}

run_as_service_user() {
  local -a cmd=(env HOME="$STATE_DIR" ENV_FILE="$ENV_FILE" "$@")
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$SERVICE_USER" -- "${cmd[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -H -u "$SERVICE_USER" "${cmd[@]}"
  else
    die "missing runuser or sudo; cannot run login as $SERVICE_USER"
  fi
}

login_service_user() {
  need_root
  load_existing_env_file
  [[ -x "$BIN_PATH" ]] || build_binary
  need_cmd systemctl
  need_cmd useradd
  need_cmd getent
  ensure_service_user
  resolve_service_group
  ensure_dirs
  write_env_file
  write_run_script
  write_healthcheck_script
  write_units

  local -a args=(-login -print-info -listen "$LISTEN" -timeout "$TIMEOUT" -handshake-timeout "$HANDSHAKE_TIMEOUT" -idle-timeout "$IDLE_TIMEOUT" -max-conns "$MAX_CONNS" -upstream-conns "$UPSTREAM_CONNS" -status-file "$STATUS_FILE" -proxy-state-file "$PROXY_STATE_FILE")
  if [[ -n "$PROXY" ]]; then
    args+=(-proxy "$PROXY")
  elif [[ -n "$COUNTRY" ]]; then
    args+=(-country "$COUNTRY")
  fi
  if [[ -n "$GUARDIAN" ]]; then
    args+=(-guardian "$GUARDIAN")
  fi
  if [[ "$USE_H3" == "1" || "$USE_H3" == "true" ]]; then
    args+=(-h3)
  fi

  require_location_selection
  log "starting interactive login as $SERVICE_USER; token will be saved to $(token_file)"
  systemctl stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  run_as_service_user "$BIN_PATH" "${args[@]}"
  has_tokens || die "login finished but token file was not created at $(token_file)"
  chown "$SERVICE_USER:$SERVICE_GROUP" "$(token_file)"
  chmod 0600 "$(token_file)"
  daemon_reload
  enable_and_start
}

health_check() {
  need_root
  [[ -x "$INSTALL_DIR/healthcheck.sh" ]] || die "healthcheck is not installed; run install first"
  SERVICE_NAME="$SERVICE_NAME" ENV_FILE="$ENV_FILE" "$INSTALL_DIR/healthcheck.sh"
}

status_service() {
  systemctl status "$SERVICE_NAME.service" "$SERVICE_NAME-health.timer" --no-pager
}

restart_service() {
  need_root
  systemctl restart "$SERVICE_NAME.service"
  systemctl restart "$SERVICE_NAME-health.timer"
}

uninstall_all() {
  need_root
  systemctl disable --now "$SERVICE_NAME-health.timer" >/dev/null 2>&1 || true
  systemctl disable --now "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE" "$HEALTH_UNIT_FILE" "$HEALTH_TIMER_FILE"
  rm -rf "$INSTALL_DIR"
  rm -f "$ENV_FILE" "$BIN_PATH"
  daemon_reload
  if [[ "$PURGE" == "1" ]]; then
    rm -rf "$STATE_DIR"
    if getent passwd "$SERVICE_USER" >/dev/null; then
      userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    fi
  else
    log "kept state directory $STATE_DIR; set PURGE=1 to remove tokens/state"
  fi
}

case "$ACTION" in
  install)
    install_all
    ;;
  login)
    login_service_user
    ;;
  install-login)
    SKIP_START=1
    install_all
    login_service_user
    ;;
  health)
    health_check
    ;;
  status)
    status_service
    ;;
  restart)
    restart_service
    ;;
  uninstall)
    uninstall_all
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    die "unknown action: $ACTION"
    ;;
esac
