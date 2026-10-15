#!/bin/bash
# ACME end to end: Pebble (a test CA) validates DNS-01 challenges that the
# coordinator publishes to BIND with RFC 2136 dynamic updates, and then
# the same through lego (its RFC 2136 provider) in the lego provider image.
#
#   tests/acme/run.sh          (needs podman, nsupdate and dig)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
BIND_IMAGE=${BIND_IMAGE:-docker.io/internetsystemsconsortium/bind9:9.20}
PEBBLE_IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}
cleanup() {
    podman rm -f sw-bind sw-pebble >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

secret=$(head -c 32 /dev/urandom | base64)
mkdir -p "$WORK/bind" "$WORK/zones"
cat > "$WORK/bind/named.conf" <<CONF
options {
    directory "/var/cache/bind";
    listen-on port 5353 { 127.0.0.1; };
    listen-on-v6 { none; };
    recursion no;
    dnssec-validation no;
    allow-query { any; };
};
key "acme" { algorithm hmac-sha256; secret "$secret"; };
zone "example.test" {
    type primary;
    file "/zones/example.test.db";
    allow-update { key "acme"; };
};
CONF
cat > "$WORK/zones/example.test.db" <<'ZONE'
$TTL 60
@   IN SOA ns.example.test. admin.example.test. 1 60 60 600 60
@   IN NS  ns.example.test.
ns  IN A   127.0.0.1
fw  IN A   127.0.0.1
vpn IN A   127.0.0.1
ZONE
chmod -R a+rwX "$WORK/zones"

podman run -d --name sw-bind --network host \
    -v "$WORK/bind/named.conf:/etc/bind/named.conf:ro,Z" \
    -v "$WORK/zones:/zones:Z" \
    --entrypoint /usr/sbin/named "$BIND_IMAGE" -g -c /etc/bind/named.conf -u bind >/dev/null
podman run -d --name sw-pebble --network host -e PEBBLE_VA_NOSLEEP=1 \
    "$PEBBLE_IMAGE" -config /test/config/pebble-config.json -dnsserver 127.0.0.1:5353 >/dev/null

if ! podman cp sw-pebble:/test/certs/pebble.minica.pem "$WORK/ca.pem" 2>/dev/null; then
    curl -fsSL -o "$WORK/ca.pem" https://raw.githubusercontent.com/letsencrypt/pebble/main/test/certs/pebble.minica.pem
fi
for _ in $(seq 30); do
    dig +short -p 5353 @127.0.0.1 SOA example.test | grep -q ns.example.test && break
    sleep 1
done
for _ in $(seq 30); do
    curl -sk https://localhost:14000/dir >/dev/null && break
    sleep 1
done

cd "$HERE/../.."
LEGO_IMAGE=${LEGO_IMAGE:-localhost/sparewall-lego:test}
podman build -q -t "$LEGO_IMAGE" image/providers/lego >/dev/null
for t in against_pebble against_pebble_with_lego; do
    # SPAREWALL_NO_HOST_RUN: run podman directly, even if the runner itself
    # is a systemd service.
    ACME_DIRECTORY=https://localhost:14000/dir \
    ACME_CA="$WORK/ca.pem" \
    ACME_DNS=127.0.0.1:5353 \
    ACME_TSIG="hmac-sha256:acme:$secret" \
    SPAREWALL_LEGO_IMAGE="$LEGO_IMAGE" \
    SPAREWALL_NO_HOST_RUN=1 \
        cargo test -p sparewalld --locked -- --ignored --exact "acme::tests::$t" --nocapture
done
echo "ACME PASS"
