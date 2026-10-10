#!/bin/sh
set -eu
test "$(id -u)" = 65532
test "$(id -g)" = 65532
test "$(pwd)" = /app
test "$HOME" = /home/rootloom
test -s "$SSL_CERT_FILE"
grep 'BEGIN CERTIFICATE' "$SSL_CERT_FILE" > /dev/null
test -s /usr/share/rootloom/source-inventory.spdx.json
test -s /usr/share/rootloom/rootfs.sha256
test ! -r /etc/shadow
test ! -w /etc/passwd
for tool in cc gcc g++ clang make apk apt apt-get dpkg rpm dnf yum wget curl su sudo login passwd; do
    if command -v "$tool" > /dev/null 2>&1; then
        echo "Unexpected runtime tool: $tool" >&2
        exit 1
    fi
done
touch /app/smoke /home/rootloom/smoke /tmp/smoke
rm /app/smoke /home/rootloom/smoke /tmp/smoke
printf 'rootloom-source-smoke-passed\n'
