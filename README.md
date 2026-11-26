# Phylax MQTT Security Service

A REST API service for managing Mosquitto Dynamic Security clients, roles and access control.

**Status:** under development. In place: service skeleton (configuration, structured logging, health check, graceful shutdown, container image, CI) the connection to the Dynamic Security Control API (mTLS, MQTT 5, correlation of responses, reconnect) and the endpoints of the interface specification "MQTT Security Service API v1" with the token check for access tokens of an OIDC provider (Keycloak or authentik) and the audit log. **Without `PMSS_OIDC_ISSUER` every `/api/v1` request is refused with `401`.**

So far this repository contains:

- The service (`cmd/`, `internal/`).
- [OpenAPI document](api/openapi.yaml) – machine-readable form of the specification, checked against routes and recorded responses ([test/openapi](test/openapi/README.md)).
- [Integration tests](test/integration/README.md) – Keycloak, Mosquitto and the service in one compose environment; the whole path token → REST → MQTT/mTLS → DynSec.
- [Broker integration test](test/integration/broker/README.md) – the broker connection against Mosquitto 2.1.4 with Dynamic Security.
- [Keycloak integration test](test/integration/keycloak/README.md) – checks scopes, audience, the role mapping of scope `write` and Standard Token Exchange against Keycloak 26.8.2.
- [JWT probe](test/probes/jwt-go-oidc/README.md) – token verification with `coreos/go-oidc/v3`, template for `internal/auth`.

Broker-side tests (Mosquitto 2.1.2 with Dynamic Security) live in [mqtt-acl-verify](https://github.com/Noschvie/mqtt-acl-verify).

## Documents

| Document | Content |
|---|---|
| [`mqtt-security-overview`](docs/mqtt-security-overview.md) | Architecture overview: MQTT security management with TasmoFleet and PMSS |
| [`mqtt-security-service-api-v1`](docs/mqtt-security-service-api-v1.md) | Interface specification "MQTT Security Service API v1" between TasmoFleet and an MQTT Security Service; normative for the API |
| [`phylax-mqtt-security-service-design`](docs/phylax-mqtt-security-service-design.md) | Design of PMSS: Mosquitto Dynamic Security, broker connection, token check, audit, tests |
| [`pmss-implementation-plan`](docs/pmss-implementation-plan.md) | Implementation plan: steps 0–7 with status and pull requests |

The documents are written in German. References such as "design 7.9" or "specification 3.2" in this repository point to sections of these documents.

## Layout

| Path | Content |
|---|---|
| `cmd/phylax-mqtt-security-service/` | `main`: commands, start, graceful shutdown |
| `internal/config/` | Configuration from environment variables |
| `internal/api/` | HTTP server, routes, access log |
| `internal/mqttclient/` | MQTT 5 connection to the admin listener (`autopaho`, mTLS, subscription in `OnConnectionUp`) |
| `internal/dynsec/` | DynSec commands, `correlationData`, timeouts, error kinds |
| `internal/auth/` | Token check: go-oidc plus `scope` claim, optional `typ` check and scopes, throttled JWKS key set, caller for the audit |
| `internal/rules/` | Checks of the write endpoints: names, passwords, ACLs, topic filters, deny warnings |
| `internal/audit/` | Audit records (`"log_type":"audit"`) with caller, before and after |
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

### Images and releases

Production images are built only by [`.github/workflows/release.yml`](.github/workflows/release.yml) (design 7.8). First the unit tests (`ci.yml`) and the integration tests (`integration.yml`) run for exactly the commit to build. Then the workflow builds for `linux/amd64` and `linux/arm64` with fresh base images, pushes to `ghcr.io/noschvie/phylax-mqtt-security-service` and checks the pushed image (both architectures, version, UID).

| Trigger | Image tags |
|---|---|
| Push to `main` | `edge`, `sha-<commit>` |
| Tag `vX.Y.Z` | `vX.Y.Z` |
| Weekly (Monday 03:17 UTC) and manual run on `main` | Rebuild of `edge` and of the newest release `vX.Y.Z` (same tag, new digest) |
| Pull request that changes `release.yml` or the `Dockerfile` | Dry run, no push |

There is no `latest` tag. A release:

```sh
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The job summary shows the digest. Production pins it, so a weekly rebuild changes the running image only after a deliberate update:

```yaml
services:
  phylax-mqtt-security-service:
    image: ghcr.io/noschvie/phylax-mqtt-security-service:v0.1.0@sha256:…
```

The images carry OCI labels (source, revision, version, license), an SBOM and provenance.

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
| `PMSS_OIDC_ISSUER` | – | Fixed issuer of the OIDC provider, e.g. `https://kc.example.org/realms/pmss` (Keycloak) or `https://auth.example.org/application/o/pmss/` (authentik); `iss` must match exactly. Empty: API closed |
| `PMSS_OIDC_AUDIENCE` | `phylax-mqtt-security-service` | Must be contained in `aud` |
| `PMSS_OIDC_JWKS_URL` | from discovery | JWKS address, e.g. an internal URL of the provider |
| `PMSS_OIDC_SCOPE_READ` | `read` | Scope name for reading endpoints |
| `PMSS_OIDC_SCOPE_WRITE` | `write` | Scope name for changing endpoints |
| `PMSS_OIDC_JWKS_MIN_REFRESH` | `1m` | Minimum time between JWKS fetches for unknown key IDs |
| `PMSS_OIDC_TYP_CHECK` | `bearer` | `bearer`: claim `typ` must be `Bearer` (Keycloak); `none`: no `typ` check (authentik sets no `typ` claim) |
| `PMSS_OIDC_ALLOW_HTTP` | `false` | Allow `http://` for issuer and JWKS (test setups only) |
| `PMSS_DYNSEC_TIMEOUT` | `5s` | Limit per DynSec command (waiting for the connection, publish, response); shorter than `PMSS_HTTP_WRITE_TIMEOUT` |

Durations use Go syntax (`500ms`, `15s`, `1m`) and must be greater than 0. The service does not start if the CA or the client certificate cannot be loaded.

## Broker connection

Decision A-9 of the design (section 7.2):

- Clean session, session expiry 0: DynSec commands are not idempotent, so an unacknowledged command must never be resent after a reconnect.
- The response topic `$CONTROL/dynamic-security/v1/response` is subscribed on every connection; commands are sent only after the subscription is acknowledged.
- Every command carries its own `correlationData` (UUID string). Responses for other subscribers (e.g. `mosquitto_ctrl` of the break-glass admin) are dropped.
- Without a connection a command waits at most `PMSS_DYNSEC_TIMEOUT` and fails as *unavailable*; it is not sent later. Without a response in time it fails as *timeout*: the command may have been executed.
- The HTTP server starts without waiting for the broker; the connection is retried in the background (0, 1s, 2s … 30s).

## Token check

Every `/api/v1` request needs `Authorization: Bearer <access token>` from the OIDC provider, Keycloak or authentik (design 7.5, T-7 to T-9, SEC-15):

- `coreos/go-oidc/v3` checks the signature (`RS256`, `ES256` only), `iss` (one fixed issuer per provider, T-8), `aud` (contains the audience), `exp` (no leeway) and `nbf` (5 min leeway).
- The token must carry a `scope` claim; tokens without one (ID tokens) are refused with `401 invalid_token`.
- `PMSS_OIDC_TYP_CHECK=bearer` (default, Keycloak) also requires `typ == "Bearer"`, so ID and refresh tokens are refused. authentik sets no `typ` claim: use `none`; the `scope` claim and the audience keep ID tokens out.
- `sub` must be present. Scopes: `read` for `GET`, `write` for changes; `write` does not include `read`. Roles are not checked – the provider issues `write` only to `security-admin`.
- `azp` is recorded in the audit as sent; the service makes no assumption about it (Keycloak: the requesting client, authentik after token exchange: the service itself).
- Without `PMSS_OIDC_JWKS_URL` the JWKS address is taken from the discovery document (`jwks_uri`, its `issuer` must match). Discovery and JWKS are fetched on the first token, so the service starts without the provider. An unknown key ID triggers at most one JWKS fetch per `PMSS_OIDC_JWKS_MIN_REFRESH`; after a failed fetch the next try is 5 s later. Known keys keep working while the provider is down.
- `401 invalid_token` and `403 insufficient_scope` carry `WWW-Authenticate` (RFC 6750). The reason of a rejection is logged, never the token.

## Endpoints

The machine-readable form is [`api/openapi.yaml`](api/openapi.yaml) (OpenAPI 3.2.1). The Markdown specification stays normative; operations of PMSS that are not in the specification are tagged `pmss-extra`.

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | – | Container health check; no token, no version in the path, no sensitive information |
| `GET` | `/api/v1/info` | `read` | API version, implementation and broker version, prefixes, marker, password policy, reserved names, limits |
| `GET` | `/api/v1/export` | `read` | All managed clients, groups and roles, sorted, with `etag` per object |
| `GET` | `/api/v1/clients/{username}` | `read` | One client with `ETag`; also unmanaged ones (`"managed": false`) |
| `GET` | `/api/v1/groups/{group}` | `read` | One group with `ETag` |
| `GET` | `/api/v1/roles/{role}` | `read` | One role with ACLs and `ETag` |
| `GET` | `/api/v1/clients`, `/api/v1/groups`, `/api/v1/roles` | `read` | All objects with `managed` (not in the specification) |
| `POST` | `/api/v1/clients` | `write` | Create a client with roles and groups; password generated or given |
| `POST` | `/api/v1/clients/{username}/password` | `write` | New password, generated or given |
| `DELETE` | `/api/v1/clients/{username}` | `write` | Delete (also: lock) a client |
| `POST`, `DELETE` | `/api/v1/clients/{username}/roles[/{role}]` | `write` | Assign or remove a role |
| `POST`, `DELETE` | `/api/v1/groups`, `/api/v1/groups/{group}` | `write` | Create or delete a group |
| `POST`, `DELETE` | `/api/v1/groups/{group}/clients[/{username}]` | `write` | Add or remove a client |
| `POST`, `DELETE` | `/api/v1/groups/{group}/roles[/{role}]` | `write` | Assign or remove a role |
| `POST`, `DELETE` | `/api/v1/roles`, `/api/v1/roles/{role}` | `write` | Create a role with ACLs, delete a role |
| `PUT` | `/api/v1/roles/{role}/acls` | `write` | Replace the whole ACL list |
| `PATCH` | `/api/v1/clients/{username}` | `write` | Change the `textname` (PMSS extra) |
| `POST` | `/api/v1/clients/{username}/enable`, `…/disable` | `write` | Enable or disable a password client (PMSS extra) |
| `POST`, `DELETE` | `/api/v1/roles/{role}/acls` | `write` | Add or remove one ACL, body `{acltype, topic[, allow, priority]}` (PMSS extra) |

### Changes

Every changing request runs the same steps (specification 3.2, 3.7, 4.3–4.8; design A-5, A-8, A-9):

1. Names: `pmss-*` and `role_security_manager` → `403 reserved_name`; objects without prefix or marker → `403 not_managed`; invalid fields → `422` with JSON Pointers. Nothing is sent to the broker before all checks pass.
2. Existing objects need `If-Match` with the current `ETag` (`428` if missing, `412` if changed in the meantime, e.g. by `mosquitto_ctrl`).
3. One DynSec command. Without an answer the service reads the object back: target state reached → success, otherwise `504 broker_timeout` (state unknown). Commands are never resent. A password change cannot be read back and always ends with `504` then.
4. The object is read back for the response and the new `ETag`. `createRole` and `PUT …/acls` compare the stored ACLs with the request (`500 readback_mismatch`; a new role is deleted again).
5. One audit record with caller, action, object, result (`success`, `failed`, `unknown`, `partial`) and the object before and after – never passwords or tokens.

Passwords: exactly 24 characters `A–Z a–z 0–9`; generated with `crypto/rand` and returned once (`Cache-Control: no-store`); a given password is never returned. Certificate clients (`CN=…`) have no password. ACLs: `acltype` from the fixed list, `topic` a valid filter, `allow` required, `priority` −100000…100000; a deny rule without higher priority than an overlapping allow rule of the same type gives the warning `deny_priority_not_higher`.

**PMSS extras** (design 7.3, not in the specification, not used by TasmoFleet):

- `PATCH` changes only `textname`; `textdescription` carries the marker and is `read_only`. Same value → `200` without a broker command.
- `enable`/`disable` work only for password clients. The broker checks `disabled` only at a password login, so a certificate client (`CN=…`) would stay usable: the service refuses with `409 certificate_client` (decision on open point 8.8, variant A). To lock a certificate client, delete it and issue a certificate with a new subject. Same state → `200` without a broker command.
- Single ACLs: `POST` adds one ACL (`409 already_exists` for the same `acltype` and `topic`), `DELETE` removes one (`404 not_found` if missing). Both answer `200` with the whole role, the new `ETag` and warnings whose pointers refer to the ACL list in the response; the stored ACLs are compared as for `PUT` (`500 readback_mismatch`).

Path parameters are URL-encoded: `CN=homeassistant,O=mqtt-apps` → `CN%3Dhomeassistant%2CO%3Dmqtt-apps`. Errors are `application/problem+json`, see [docs/errors.md](docs/errors.md).

**ETag** (specification 3.2): SHA-256 over the fields the object owns, lists sorted – client: `username`, `textname`, `textdescription`, `disabled`, `roles`; group: `groupname`, `textname`, `roles`, `clients`; role: `rolename`, `textname`, `acls`. Group membership belongs to the group, so adding a client to a group changes only the group ETag; a password change changes no ETag.

**Export** (specification 4.2): three lists read one after the other (DynSec has no snapshot); objects sorted by name, assignments by name, ACLs by `acltype` and `topic` (Unicode code points). Two exports of the same state are byte-identical apart from `exportedAt`.

## Logging

Logs go to stdout as JSON (`log/slog`). Each request produces one record with method, path, status and duration; health checks only at level `debug`. Headers and bodies are never logged.

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
