# Phylax MQTT Security Service

A REST API service for managing Mosquitto Dynamic Security clients, roles and access control.

**Status:** under development. The service skeleton is in place (configuration, structured logging, health check, graceful shutdown, container image, CI). The Dynamic Security connection and the endpoints of the interface specification "MQTT Security Service API v1" follow.

So far this repository contains:

- The service skeleton (`cmd/`, `internal/`).
- [Keycloak integration test](test/integration/keycloak/README.md) – checks scopes, audience, the role mapping of scope `write` and Standard Token Exchange against Keycloak 26.8.2.
- [JWT probe](test/probes/jwt-go-oidc/README.md) – token verification with `coreos/go-oidc/v3`, template for `internal/auth`.

Broker-side tests (Mosquitto 2.1.2 with Dynamic Security) live in [mqtt-acl-verify](https://github.com/Noschvie/mqtt-acl-verify).

## Layout

| Path | Content |
|---|---|
| `cmd/phylax-mqtt-security-service/` | `main`: commands, start, graceful shutdown |
| `internal/config/` | Configuration from environment variables |
| `internal/api/` | HTTP server, routes, access log |
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

Durations use Go syntax (`500ms`, `15s`, `1m`) and must be greater than 0.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | Container health check; no token, no version in the path, no sensitive information |

## Logging

Logs go to stdout as JSON (`log/slog`). Each request produces one record with method, path, status and duration; health checks only at level `debug`. Headers and bodies are never logged.

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
