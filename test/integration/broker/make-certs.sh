#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Creates the test PKI and the broker data for the DynSec integration test
# (design sections 5.1, 6.2, 7.9). Test material only: keys are created per
# run, are world-readable for the broker container and are never committed.
#
#   ./make-certs.sh [DIR]      default DIR: ./run
#
# DIR/certs:
#   server-ca.crt                 trusted by the Security Service
#   server.crt/.key               broker, SAN mosquitto, localhost, 127.0.0.1
#   admin-ca.crt                  trusted by the broker at the admin listener
#   pmss-admin.crt/.key           CN=pmss-admin (Security Service)
#   pmss-breakglass-admin.crt/.key  CN=pmss-breakglass-admin (second admin)
#   wrong-ca-client.crt/.key      CN=pmss-admin, signed by the server CA (must be rejected)
# DIR/data/dynamic-security.json  state after the offline bootstrap (design 6.2)
set -eu

DIR=${1:-./run}
HERE=$(cd "$(dirname "$0")" && pwd)
rm -rf "$DIR"
mkdir -p "$DIR/certs" "$DIR/data"
DIR=$(cd "$DIR" && pwd) # absolute, the script changes into certs/
cd "$DIR/certs"

ca() { # name subject
	openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "$2" \
		-keyout "$1.key" -out "$1.crt" \
		-addext basicConstraints=critical,CA:true \
		-addext keyUsage=critical,keyCertSign,cRLSign 2>/dev/null
}

leaf() { # name ca subject extensions
	openssl req -newkey rsa:2048 -nodes -subj "$3" -keyout "$1.key" -out "$1.csr" 2>/dev/null
	printf '%s\n' "$4" > "$1.ext"
	openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
		-days 2 -extfile "$1.ext" -out "$1.crt" 2>/dev/null
	rm -f "$1.csr" "$1.ext"
}

client_ext='basicConstraints=CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth'

ca server-ca "/O=pmss-test/CN=pmss-test server CA"
ca admin-ca "/O=pmss-test/CN=pmss-test admin CA"

leaf server server-ca "/O=pmss-test/CN=mosquitto" 'basicConstraints=CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:mosquitto,DNS:localhost,IP:127.0.0.1'
leaf pmss-admin admin-ca "/CN=pmss-admin" "$client_ext"
leaf pmss-breakglass-admin admin-ca "/CN=pmss-breakglass-admin" "$client_ext"
leaf wrong-ca-client server-ca "/CN=pmss-admin" "$client_ext"

# CA keys are not needed after signing.
rm -f server-ca.key admin-ca.key ./*.srl
# The broker runs as another user in the container.
chmod 0644 ./*

cp "$HERE/dynamic-security.json" "$DIR/data/dynamic-security.json"
chmod 0777 "$DIR/data"
chmod 0666 "$DIR/data/dynamic-security.json"

echo "test PKI and broker data in $DIR"
