# Phylax MQTT Security Service

A REST API service for managing Mosquitto Dynamic Security clients, roles and access control.

**Status:** under development. In place: service skeleton (configuration, structured logging, health check, graceful shutdown, container image, CI) the connection to the Dynamic Security Control API (mTLS, MQTT 5, correlation of responses, reconnect) and the reading endpoints of the interface specification "MQTT Security Service API v1". The token check (Keycloak) and the changing endpoints follow. **Until the token check is in place, every `/api/v1` request is refused with `401`.**

So far this repository contains:

- The service (`cmd/`, `internal/`).
- [Broker integration test](test/integration/broker/README.md) – the broker connection against Mosquitto 2.1.2 with Dynamic Security.
- [Keycloak integration test](test/integration/keycloak/README.md) – checks scopes, audience, the role mapping of scope `write` and Standard Token Exchange against Keycloak 26.8.2.
- [JWT probe](test/probes/jwt-go-oidc/README.md) – token verification with `coreos/go-oidc/v3`, template for `internal/auth`.

Broker-side tests (Mosquitto 2.1.2 with Dynamic Security) live in [mqtt-acl-verify](https://github.com/Noschvie/mqtt-acl-verify).

## Layout

| Path | Content |
|---|---|
| `cmd/phylax-mqtt-security-service/` | `main`: commands, start, graceful shutdown |
| `internal/config/` | Configuration from environment variables |
| `internal/api/` | HTTP server, routes, access log |
| `internal/mqttclient/` | MQTT 5 connection to the admin listener (`autopaho`, mTLS, subscription in `OnConnectionUp`) |
| `internal/dynsec/` | DynSec commands, `correlationData`, timeouts, error kinds |
| `internal/model/` | API objects from DynSec data: defaults, sorting, ETag, managed flag, `authType` |
| `internal/problem/` | Error responses (`problem+json`, codes in [docs/errors.md](docs/errors.md)) |
| `internal/testbroker/` | Helpers for the integration tests |
| `test/` | Integration tests and probes (separate Go modules) |

## Build and run

Requires Go 1.27.

```sh
go vet ./...
go test -race ./...
go run ./cmd/phylax-mqtt-security-service
curl http://127.0.0.1:8080/healthz        # {"status":"ok"}
```

Container image (local builds are for testing only; production images come from GitHub Actions):

```sh
docker build --build-arg VERSION=$(git describe --tags --always) -t phylax-mqtt-security-service:dev .
docker run --rm -p 8080:8080 phylax-mqtt-security-service:dev
```

The image is based on `debian:trixie-slim`, runs as UID/GID 10001 and has a `HEALTHCHECK` that calls the binary itself (no curl in the image).

### Commands

| Command | Purpose |
|---|---|
| `phylax-mqtt-security-service` | Run the service; stops gracefully on SIGTERM or SIGINT |
| `phylax-mqtt-security-service healthcheck` | Call `/healthz` of the running service on the local host; exit code 0 or 1 |
| `phylax-mqtt-security-service version` | Print the version (set at build time with `-ldflags "-X main.version=…"`) |

## Configuration

All settings are environment variables with defaults. Invalid values stop the service at start, with all errors in one log record.

| Variable | Default | Meaning |
|---|---|---|
| `PMSS_LISTEN_ADDR` | `:8080` | Address of the HTTP server |
| `PMSS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `PMSS_SHUTDOWN_TIMEOUT` | `15s` | Time open requests get after SIGTERM |
| `PMSS_HTTP_READ_HEADER_TIMEOUT` | `5s` | `http.Server.ReadHeaderTimeout` |
| `PMSS_HTTP_READ_TIMEOUT` | `15s` | `http.Server.ReadTimeout` |
| `PMSS_HTTP_WRITE_TIMEOUT` | `30s` | `http.Server.WriteTimeout` |
| `PMSS_HTTP_IDLE_TIMEOUT` | `60s` | `http.Server.IdleTimeout` |
| `PMSS_MQTT_BROKER_URL` | `mqtts://mosquitto:8884` | Admin listener of the broker; only `mqtts` |
| `PMSS_MQTT_SERVER_NAME` | host of the URL | Name checked against the SAN of the broker certificate |
| `PMSS_MQTT_CA_FILE` | `/run/mqtt-server-ca/ca.crt` | Server CA; the only CA trusted for the broker |
| `PMSS_MQTT_CERT_FILE` | `/run/secrets/mqtt-client/pmss-admin.crt` | Client certificate of the admin CA; its CN is the DynSec user |
| `PMSS_MQTT_KEY_FILE` | `/run/secrets/mqtt-client/pmss-admin.key` | Key of the client certificate |
| `PMSS_MQTT_CLIENT_ID` | `pmss-` + random hex | MQTT client ID |
| `PMSS_MQTT_KEEPALIVE` | `30s` | MQTT keep alive, whole seconds |
| `PMSS_ROLE_PREFIX` | `tf_` | Prefix of managed roles |
| `PMSS_GROUP_PREFIX` | `tf_` | Prefix of managed groups |
| `PMSS_CLIENT_MARKER` | `managed-by: pmss` | `textdescription` of managed clients |
| `PMSS_MAX_REQUEST_BYTES` | `1048576` | Largest request body, at least 1 MiB |
| `PMSS_DYNSEC_TIMEOUT` | `5s` | Limit per DynSec command (waiting for the connection, publish, response); shorter than `PMSS_HTTP_WRITE_TIMEOUT` |

Durations use Go syntax (`500ms`, `15s`, `1m`) and must be greater than 0. The service does not start if the CA or the client certificate cannot be loaded.

## Broker connection

Decision A-9 of the design (section 7.2):

- Clean session, session expiry 0: DynSec commands are not idempotent, so an unacknowledged command must never be resent after a reconnect.
- The response topic `$CONTROL/dynamic-security/v1/response` is subscribed on every connection; commands are sent only after the subscription is acknowledged.
- Every command carries its own `correlationData` (UUID string). Responses for other subscribers (e.g. `mosquitto_ctrl` of the break-glass admin) are dropped.
- Without a connection a command waits at most `PMSS_DYNSEC_TIMEOUT` and fails as *unavailable*; it is not sent later. Without a response in time it fails as *timeout*: the command may have been executed.
- The HTTP server starts without waiting for the broker; the connection is retried in the background (0, 1s, 2s … 30s).

## Endpoints

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | – | Container health check; no token, no version in the path, no sensitive information |
| `GET` | `/api/v1/info` | `read` | API version, implementation and broker version, prefixes, marker, password policy, reserved names, limits |
| `GET` | `/api/v1/export` | `read` | All managed clients, groups and roles, sorted, with `etag` per object |
| `GET` | `/api/v1/clients/{username}` | `read` | One client with `ETag`; also unmanaged ones (`"managed": false`) |
| `GET` | `/api/v1/groups/{group}` | `read` | One group with `ETag` |
| `GET` | `/api/v1/roles/{role}` | `read` | One role with ACLs and `ETag` |
| `GET` | `/api/v1/clients`, `/api/v1/groups`, `/api/v1/roles` | `read` | All objects with `managed` (not in the specification) |

Path parameters are URL-encoded: `CN=homeassistant,O=mqtt-apps` → `CN%3Dhomeassistant%2CO%3Dmqtt-apps`. Errors are `application/problem+json`, see [docs/errors.md](docs/errors.md).

**ETag** (specification 3.2): SHA-256 over the fields the object owns, lists sorted – client: `username`, `textname`, `textdescription`, `disabled`, `roles`; group: `groupname`, `textname`, `roles`, `clients`; role: `rolename`, `textname`, `acls`. Group membership belongs to the group, so adding a client to a group changes only the group ETag; a password change changes no ETag.

**Export** (specification 4.2): three lists read one after the other (DynSec has no snapshot); objects sorted by name, assignments by name, ACLs by `acltype` and `topic` (Unicode code points). Two exports of the same state are byte-identical apart from `exportedAt`.

## Logging

Logs go to stdout as JSON (`log/slog`). Each request produces one record with method, path, status and duration; health checks only at level `debug`. Headers and bodies are never logged.

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
