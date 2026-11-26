#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates the signing key of the test providers for the authentik probe.
# Test material only: created per run, world-readable for the authentik
# containers and never committed.
#
#   make-keys.sh [DIR]        default DIR: run/ next to this script
#
# DIR/signing.crt, DIR/signing.key   RSA 2048, self-signed, read by the
#                                    blueprint (!File) as keypair
#                                    "pmss-test-signing"
#
# An own keypair instead of "authentik Self-signed Certificate": the
# blueprint may run before authentik has created that certificate, and a
# provider without signing key signs with HS256 and the client secret.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=${1:-$HERE/run}
rm -rf "$DIR"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
	-subj "/CN=pmss-test-signing" \
	-keyout "$DIR/signing.key" -out "$DIR/signing.crt" 2>/dev/null
chmod 644 "$DIR/signing.key" "$DIR/signing.crt"
echo "signing key in $DIR"
