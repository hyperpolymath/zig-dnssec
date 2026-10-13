#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell
#
# Starts (or stops) the local test infrastructure for the cross-check:
#   NSD     127.0.0.1:53    authoritative for every zone in zones/
#   Unbound 127.0.0.1:5301  validating recursive resolver (plain DNS)
#           127.0.0.1:8443  the same resolver over DoH (HTTP/2 only)
#   haproxy 127.0.0.1:8444  HTTP/1.1 DoH front end to the above (test CA)
# Unbound iterates from the fake root and validates with zones/root.anchor.
#
# Usage: ./servers.sh start|stop
set -euo pipefail
cd "$(dirname "$0")"
W="$PWD/work"
mkdir -p "$W/tls"

stop() {
  [[ -f "$W/unbound.pid" ]] && kill "$(cat "$W/unbound.pid")" 2>/dev/null || true
  [[ -f "$W/nsd.pid" ]] && kill "$(cat "$W/nsd.pid")" 2>/dev/null || true
  [[ -f "$W/haproxy.pid" ]] && kill "$(cat "$W/haproxy.pid")" 2>/dev/null || true
  sleep 0.5
  rm -f "$W/unbound.pid" "$W/nsd.pid" "$W/haproxy.pid"
}

start() {
  stop
  # --- NSD ------------------------------------------------------------------
  {
    cat <<EOF
server:
    ip-address: 127.0.0.1
    port: 53
    username: ""
    chroot: ""
    zonesdir: "$PWD/zones"
    database: ""
    zonelistfile: "$W/nsd.zonelist"
    xfrdfile: "$W/nsd.xfrd.state"
    pidfile: "$W/nsd.pid"
    logfile: "$W/nsd.log"
    server-count: 1
    verbosity: 1
remote-control:
    control-enable: no
EOF
    for f in zones/*.signed; do
      b=$(basename "$f" .signed)
      z=$b.; [[ $b == root ]] && z=.
      printf 'zone:\n    name: "%s"\n    zonefile: "%s"\n' "$z" "$(basename "$f")"
    done
  } > "$W/nsd.conf"
  nsd -c "$W/nsd.conf"

  # --- TLS for DoH (test-only CA) --------------------------------------------
  if [[ ! -f "$W/tls/server.pem" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
      -subj "/CN=zig-dnssec test CA" -keyout "$W/tls/ca.key" -out "$W/tls/ca.pem" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -subj "/CN=localhost" -keyout "$W/tls/server.key" -out "$W/tls/server.csr" 2>/dev/null
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$W/tls/ext.cnf"
    openssl x509 -req -in "$W/tls/server.csr" -CA "$W/tls/ca.pem" -CAkey "$W/tls/ca.key" \
      -CAcreateserial -days 30 -extfile "$W/tls/ext.cnf" -out "$W/tls/server.pem" 2>/dev/null
  fi

  # --- Unbound ----------------------------------------------------------------
  printf '.  3600000 NS a.root.\na.root. 3600000 A 127.0.0.1\n' > "$W/root.hints"
  cat > "$W/unbound.conf" <<EOF
server:
    interface: 127.0.0.1@5301
    interface: 127.0.0.1@8443
    https-port: 8443
    tls-service-key: "$W/tls/server.key"
    tls-service-pem: "$W/tls/server.pem"
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
    # RFC 6761 special-use names are blocked by default; the fixtures use test.
    local-zone: "test." nodefault
    root-hints: "$W/root.hints"
    trust-anchor-file: "$PWD/zones/root.anchor"
    module-config: "validator iterator"
    harden-dnssec-stripped: yes
    aggressive-nsec: no
    qname-minimisation: no
    val-log-level: 2
    log-servfail: yes
    verbosity: 1
    username: ""
    chroot: ""
    directory: "$W"
    pidfile: "$W/unbound.pid"
    logfile: "$W/unbound.log"
    use-syslog: no
    cache-max-ttl: 1
    cache-max-negative-ttl: 1
remote-control:
    control-enable: no
EOF
  unbound -c "$W/unbound.conf"

  # --- haproxy: HTTP/1.1 DoH front end -> Unbound's HTTP/2-only DoH ------
  # (the zig-dnssec DoH transport speaks HTTP/1.1 only)
  cat "$W/tls/server.pem" "$W/tls/server.key" > "$W/tls/haproxy.pem"
  cat > "$W/haproxy.cfg" <<EOF
global
    pidfile $W/haproxy.pid
    daemon
defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
frontend doh
    bind 127.0.0.1:8444 ssl crt $W/tls/haproxy.pem alpn http/1.1
    default_backend unbound
backend unbound
    server u 127.0.0.1:8443 ssl verify required ca-file $W/tls/ca.pem sni str(localhost) alpn h2
EOF
  haproxy -f "$W/haproxy.cfg"
  for _ in $(seq 1 50); do
    dig +time=1 +tries=1 @127.0.0.1 -p 5301 . SOA >/dev/null 2>&1 && break
    sleep 0.2
  done
  echo "NSD and Unbound running (logs in $W)"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
