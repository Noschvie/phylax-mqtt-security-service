# MQTT Security Service API v1
## Interface specification between TasmoFleet and an external MQTT Security Service

**Status:** For review by the TasmoFleet maintainers  
**Version:** 1.1  
**Date:** 24 November 2026  
**Basis:** Architecture overview (`mqtt-security-overview`) and PMSS detail document (`phylax-mqtt-security-service-design`), each in the current version  
**Reference implementation:** Phylax MQTT Security Service (PMSS), https://github.com/Noschvie/phylax-mqtt-security-service  
**Machine-readable version:** `api/openapi.yaml` in the PMSS repository (OpenAPI 3.2.1, section 7.1)  
**Broker:** Eclipse Mosquitto 2.1 or later with the Dynamic Security plugin (DynSec)  
**Identity provider:** OIDC provider with token exchange according to RFC 8693; tested with Keycloak 26.8.2 and authentik 2026.8.6, at least Keycloak 26.2 or authentik 2026.8.3 (section 2.3)

> **Purpose**
> This document describes what TasmoFleet expects from an external MQTT Security Service and what it has to do itself. It answers overview question 16: TasmoFleet depends only on this specification, not on PMSS. PMSS is one implementation of it.

> **Legend**
> - ✅ = decided in the PMSS document or in the overview (D-…, SEC-…, section references "PMSS x.y")
> - ✅ S-… = decided in this specification; overview in section 8

## Introduction

**Initial situation.** Today, many Tasmota devices and applications share one MQTT user on the Mosquitto broker. As a result, every client can read and write the topics of all others: it can switch foreign devices, set new credentials on them via `cmnd/…` or read their configuration backups via `stat/<topic>/FILEDOWNLOAD`. Separating by client ID does not help, because the client ID is not authenticated.

**Goal.** Every device and every application gets its own credentials and only the permissions it needs. The technical basis is the Mosquitto Dynamic Security plugin: it allows clients, groups, roles and ACLs to be changed at runtime, without restarting the broker.

**Division of tasks.** TasmoFleet knows the devices: topics, GroupTopics, FallbackTopic, MAC and the way to bring new credentials to a device via `Backlog`. It should therefore provide the user interface, derive the required permissions from this data and present changes for approval. The changes on the broker itself are carried out by a separate service, the MQTT Security Service. It is the only participant with admin permissions on the broker, logs in there only with a certificate and has no access to the payload. TasmoFleet remains a normal MQTT client and needs no broker admin permissions.

**Why a specification.** TasmoFleet is an upstream project, the security service a separate project. So that TasmoFleet does not depend on a specific implementation, this document only describes the interface between the two: a REST API over HTTPS, secured with tokens of the OIDC provider that users use to log in to TasmoFleet (tested: Keycloak and authentik). The Phylax MQTT Security Service (PMSS) is the reference implementation; another implementation of the same specification would be equivalent for TasmoFleet.

**Content.** The specification defines:

- how TasmoFleet authenticates to the security service (token exchange, scopes `read`/`write`) and what the OIDC provider must support for this,
- which endpoints TasmoFleet uses, with request and response as JSON examples,
- how concurrent changes are detected (`ETag`/`If-Match`),
- how passwords are generated and handed over once,
- which errors can occur and how TasmoFleet reacts to them,
- which tasks TasmoFleet takes on itself (target state, diff, approval, audit of approvals).

**Not covered** by this document are the operation of the broker, the listener and certificate configuration, the internal connection of the security service to the broker and the migration of the existing devices. These topics are described in the architecture overview (`mqtt-security-overview`) and the PMSS detail document (`phylax-mqtt-security-service-design`).

**Audience:** the maintainers of TasmoFleet and everyone who implements or tests the security service.

## 1. Principles

- **Only Mosquitto with Dynamic Security.** The specification deliberately uses the DynSec terms and field names (`clients`, `groups`, `roles`, `acls`, `acltype`, `rolename` …). There is no separate abstraction model (decision on question 16, variant A). ✅ D-26
- **TasmoFleet is never DynSec admin.** All changes to credentials and permissions go through this API. ✅ D-27
- **The service holds no state.** Target state, diff, approval, drift report and backup are in TasmoFleet. The service provides the actual state via `GET /api/v1/export`. ✅ D-43
- **Only managed objects can be changed.** Roles and groups with the prefix `tf_`, clients with `managed-by: pmss` in `textdescription`. Everything else can be read, but not changed (`403`). ✅ D-39
- **Field names:** Fields from DynSec keep their DynSec name (lower case, e.g. `textname`, `rolename`). The service's own fields are in camelCase (e.g. `etag`, `managed`, `authType`). ✅ S-8
- **No specific identity provider.** The specification requires an OIDC provider with the properties from section 2.3. TasmoFleet handles differences between providers according to the rules in section 2.2. ✅ S-15

### 1.1 Block diagram

```text
┌──────────────────┐ (1) Login (OIDC)     ┌───────────────────────────────────────────┐
│ Browser          │─────────────────────►│ OIDC provider (Keycloak, authentik)       │
│ security-admin   │                      │ operator / admin / security-admin         │
└────────┬─────────┘                      │ Scopes read / write, second factor        │
         │ user interface                 └──────▲─────────────────────────┬──────────┘
         ▼                                       │ (2) token exchange      │ (3) JWKS
┌────────────────────────────────────────────────┴─────┐                   │
│ TasmoFleet                                           │                   │
│  Security Manager: target state, diff, approval,     │                   │
│  drift report, audit of approvals                    │                   │
│  security service client: token, ETag/If-Match       │                   │
└───────┬───────────────────────────────┬──────────────┘                   │
        │                               │                                  │
        │ (6) MQTT as                   │ (4) HTTPS, bearer token, JSON    │
        │     normal client             │ ★ interface specification        │
        │     (Backlog to devices)      ▼                                  │
        │                       ┌──────────────────────────────────────┐   │
        │                       │ NPM (TLS termination)                │   │
        │                       └───────┬──────────────────────────────┘   │
        │                               ▼                                  │
        │                       ┌──────────────────────────────────────┐   │
        │                       │ MQTT Security Service (PMSS)         │◄──┘
        │                       │ token check, validation, ETag,       │
        │                       │ compensation path, audit log         │
        │                       └───────┬──────────────────────────────┘
        │                               │ (5) MQTT 5, mTLS :8884, admin certificate
        │                               ▼     $CONTROL/dynamic-security/v1
        │                       ┌──────────────────────────────────────┐
        └──────────────────────►│ Mosquitto 2.1 + Dynamic Security     │
          :1883 / :8883         └───────▲──────────────────────────────┘
                                        │ (7) :1883 password
                                        │     :8883 TLS + password
                                        │     :8885 app certificate
                                ┌───────┴──────────────────────────────┐
                                │ Tasmota devices and applications     │
                                └──────────────────────────────────────┘
```

| No. | Connection | Protocol / security | In this specification |
|---|---|---|---|
| 1 | Browser → OIDC provider (via TasmoFleet) | OIDC login, second factor for `security-admin` | – |
| 2 | TasmoFleet → OIDC provider | Token exchange (RFC 8693), `aud` = security service | ✅ sections 2.2, 2.3 |
| 3 | OIDC provider → security service | JWKS (public keys for token checking) | Section 2.1 |
| 4 | TasmoFleet → NPM → security service | HTTPS, bearer token, JSON | ✅ **Core of this specification**, sections 3 and 4 |
| 5 | Security service → Mosquitto | MQTT 5 over mTLS, port 8884, admin certificate, DynSec Control API | – (PMSS document 7.2) |
| 6 | TasmoFleet → Mosquitto | MQTT as a normal client (1883/8883), among others `Backlog MqttUser …; MqttPassword …` to devices | – (overview 6.2) |
| 7 | Devices and applications → Mosquitto | 1883 password, 8883 TLS + password, 8885 app certificate | – (overview 7.1) |

TasmoFleet only knows connections 1, 2, 4 and 6. Whether PMSS or another implementation of this specification is behind (4) does not matter to TasmoFleet. The broker admin access (5) lies entirely within the security service.

## 2. Authentication and authorisation

### 2.1 Token

- Every call except `/healthz` carries `Authorization: Bearer <JWT>`. ✅
- The issuer is exclusively the configured OIDC provider, with exactly one fixed issuer. The service checks signature (JWKS), `iss`, `aud`, `exp`/`nbf` and the algorithm. ✅ SEC-15
- The service only accepts access tokens. Every token must have a `scope` claim (space-separated list); a token without `scope` is rejected with `401 invalid_token`. Further checks of the token type (e.g. the `typ` claim with Keycloak) are defined by the implementation per provider. ✅ S-15
- Scopes: `read` for all `GET`, `write` for all modifying calls. `write` does not include `read`. ✅
- The OIDC provider issues `write` only to users with the role or group `security-admin`. The service checks no roles or groups. ✅ D-48

### 2.2 Token exchange in TasmoFleet

TasmoFleet never calls the service with its own token and never with a service account with `write`, but exchanges the token of the logged-in user at the same OIDC provider (RFC 8693). ✅ D-31, SEC-34

**Preconditions** ✅ S-17:

- TasmoFleet runs in OIDC mode (`TASMOFLEET_AUTH_MODE=oidc`). In header mode (login via an upstream proxy) and with local accounts, TasmoFleet has no user token it could exchange; the Security Manager functions are then not offered.
- TasmoFleet exchanges a valid access token of the session. If it has expired or expires shortly, TasmoFleet refreshes it beforehand with the refresh token (`offline_access`).
- TasmoFleet calls the token endpoint via the same public URL that users use to log in. With providers that build the issuer from the host name of the request (authentik), a token obtained via an internal name would have a different `iss` and would be rejected by the service (`401`).

**Request** – client authentication depending on the provider via HTTP Basic or `client_id`/`client_secret` in the body:

```bash
curl -s -u tasmofleet:<client-secret> \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=<access-token-des-benutzers> \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=<client-id-des-security-service> \
  -d scope="read write" \
  <token-endpunkt>
```

| Provider | Token endpoint | `audience` |
|---|---|---|
| Keycloak | `https://<keycloak>/realms/<realm>/protocol/openid-connect/token` | Client ID of the security service |
| authentik | `https://<authentik>/application/o/token/` | Client ID of the security service's provider |

TasmoFleet takes the token endpoint from the OIDC configuration of its login (discovery).

Response (shortened):

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "read write",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token"
}
```

**Requesting scopes** ✅ S-16:

- TasmoFleet requests `read write` only for users with the role or group `security-admin` (from the login token, like the other TasmoFleet roles), for all others only `read`.
- If the provider rejects the exchange, TasmoFleet repeats it **once** with `read` only. If that also fails, the exchange has failed.
- In any case, TasmoFleet evaluates `scope` of the exchanged token and offers modifying functions only if `write` is included.

> **Important: providers behave differently when `write` is missing**
>
> | Provider | User without `security-admin` requests `read write` |
> |---|---|
> | Keycloak 26.8.2 | `200` with `"scope": "read"` |
> | authentik 2026.8.6 | `400 invalid_grant`; the whole request is rejected, the error message does not differ from other rejections |
>
> The rules above cover both cases. ✅ Tested (PMSS 7.9, probe `test/integration/authentik`)

Configuration in TasmoFleet ✅ S-12:

| Setting | Example |
|---|---|
| Base URL of the service | `https://pmss.example.org` |
| Audience for the token exchange | `phylax-mqtt-security-service` |
| Scope names | `read`, `write` |
| Role or group for `write` | `security-admin` |
| Token endpoint | not configured, but taken from the OIDC configuration of the login |
| Marker of managed objects, prefixes, limits | not configured, but taken from `GET /api/v1/info` (section 4.1) |

### 2.3 Requirements for the OIDC provider

✅ S-15: The provider must support the following. The columns show how the tested providers implement it.

| Requirement | Keycloak 26.8.2 | authentik 2026.8.6 |
|---|---|---|
| Minimum version | 26.2 (standard token exchange) | 2026.8.3 (token exchange from 2026.8.0; 2026.8.3 fixes the exchange without signing key) |
| Token exchange according to RFC 8693 with `audience` = security service; `sub` remains the user | Standard token exchange, enabled on the TasmoFleet client | Grant "Token exchange" on the TasmoFleet provider; the security service's provider trusts the TasmoFleet provider (Federated OAuth2/OpenID Providers) |
| Exchanged token: `aud` = security service, `iss` = fixed issuer | Issuer of the realm | Issuer of the security service's provider, e.g. `https://<authentik>/application/o/pmss/` |
| Fixed issuer, independent of the access path | `KC_HOSTNAME` = public URL | Issuer follows the host name of the request: all callers via the same public URL, the reverse proxy passes `Host` or `X-Forwarded-Host` through |
| `write` only for `security-admin` | Role mapping on the client scope `write` | Expression policy on the security service's application (context `oauth_scopes`) |
| `scope` claim in the access token | ✅ | ✅ |
| User name for the audit (`preferred_username`) | Mapper in the client scope | Scope mapping `read` |
| Signature with `RS256` or `ES256`, JWKS retrievable | ✅ | ✅ (own key pair on the provider) |
| Exchange only for tokens issued for TasmoFleet | ✅ | ✅ |
| Second factor for `security-admin` | Conditional login flow | Authenticator validation in the login flow |

What the service itself configures per provider (issuer, JWKS address, check of the token type) is described in the PMSS document (7.5).

## 3. Common rules

### 3.1 Formats and headers

| Topic | Rule | |
|---|---|---|
| Content-Type | `application/json; charset=utf-8` | ✅ |
| Unknown fields in the request | `422` (`DisallowUnknownFields`) | ✅ |
| Body size | at least 1 MiB; actual limit in `GET /api/v1/info` (`limits.maxRequestBytes`), above it `413 payload_too_large` | ✅ S-11 |
| Errors | `application/problem+json` according to RFC 9457 (section 3.4) | ✅ S-1 |
| Timestamps | RFC 3339, UTC, e.g. `2026-11-20T21:30:12Z` | ✅ S-12 |
| Path parameters | URL-encoded (RFC 3986); `CN=homeassistant,O=mqtt-apps` becomes `CN%3Dhomeassistant%2CO%3Dmqtt-apps` | ✅ S-12 |

### 3.2 `ETag` and `If-Match`

✅ D-46, SEC-31

- Every response with a single client, group or role carries an `ETag` header: a hash over the fields that belong to the object (table below), without the password hash.
- `GET /api/v1/export` provides the `etag` per object in the JSON body.
- Every modifying call on an **existing** object requires `If-Match` with this value:
  - mismatch → `412`, nothing is changed.
  - `If-Match` missing → `428`.
- Creating (`POST /api/v1/clients`, `/api/v1/groups`, `/api/v1/roles`) needs no `If-Match`.

**Owners of relationships** ✅ S-4: In DynSec, an assignment between client and group is stored with both objects. So that every change changes exactly one ETag, every relationship belongs to exactly one object. Only its ETag contains it.

| Object | Fields in the ETag | Shown, but not in the ETag |
|---|---|---|
| Client | `username`, `textname`, `textdescription`, `disabled`, `roles` | `groups`, `authType` |
| Group | `groupname`, `textname`, `roles`, `clients` | – |
| Role | `rolename`, `textname`, `acls` | – |

`If-Match` is always the ETag of the object in the path, and only this ETag changes:

| Call | `If-Match` of | New ETag of |
|---|---|---|
| `POST/DELETE /api/v1/clients/{username}/roles…` | Client | Client |
| `POST/DELETE /api/v1/groups/{group}/clients…` | Group | Group |
| `POST/DELETE /api/v1/groups/{group}/roles…` | Group | Group |
| `PUT /api/v1/roles/{role}/acls` | Role | Role |

For TasmoFleet this means: whether a client is in a group is compared via the group (`groups[].clients`), not via `clients[].groups`. After a group assignment, the client's ETag stays valid.

### 3.3 Passwords

✅ D-41, D-42, SEC-28

- Exactly 24 characters from `A–Z a–z 0–9`, otherwise `422`.
- If the password is missing in the request, the service generates one (`crypto/rand`).
- A generated password appears exactly once in the response, with `Cache-Control: no-store`. The service neither stores nor logs it.
- Certificate clients (name starts with `CN=`) never have a password.

### 3.4 Error responses

✅ S-1: Every error response (`4xx`, `5xx`) has the content type `application/problem+json` according to RFC 9457.

| Field | Required | Meaning |
|---|---|---|
| `status` | yes | HTTP status, equal to the status of the response |
| `code` | yes | Machine-readable error code from the list in 3.5 |
| `title` | yes | Short, constant text for the `code` (English) |
| `detail` | no | Description of the specific case; for display only, do not evaluate |
| `type` | no | URI, **defined by the implementation**; not part of the specification. If the field is missing, `about:blank` applies |
| `instance` | no | Path of the request |
| `errors` | for `422` | List of the individual errors with `pointer` (JSON Pointer, RFC 6901), `code`, `detail` |

Rules for TasmoFleet:

- Only `status` and `code` are evaluated, never `type`, `title` or `detail`.
- An unknown `code` is treated like the status (e.g. a new `403` code like `403 insufficient_scope`). New codes can be added within 1.x (section 7).
- `detail` can be displayed; it never contains passwords or tokens.

Example:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json
```

```json
{
  "type": "https://pmss.example.org/errors/not_managed",
  "title": "Object is not managed by the security service",
  "status": 403,
  "code": "not_managed",
  "detail": "Client 'legacy-shared-user' has no 'managed-by: pmss' marker.",
  "instance": "/api/v1/clients/legacy-shared-user/password"
}
```

For `422` with individual errors:

```json
{
  "title": "Validation failed",
  "status": 422,
  "code": "validation_failed",
  "errors": [
    { "pointer": "/acls/1/allow", "code": "required", "detail": "Field 'allow' is required." },
    { "pointer": "/acls/2/acltype", "code": "invalid_acltype", "detail": "Unknown acltype 'publish'." }
  ]
}
```

The second example has no `type`; `about:blank` applies.

For `401` and `403` because of the scope, additionally `WWW-Authenticate` according to RFC 6750, e.g. `Bearer error="insufficient_scope", scope="write"`.

### 3.5 Status codes and error codes

✅ S-1: The error codes are binding. A code always belongs to exactly the stated status.

| Status | `code` | When |
|---|---|---|
| `200` | – | Read, change successful |
| `201` | – | Object created; `Location` and `ETag` headers |
| `204` | – | Deleted or assignment removed |
| `401` | `invalid_token` | Token missing, invalid, expired, wrong `iss` or `aud`, no `scope` claim ✅ |
| `403` | `insufficient_scope` | Scope missing ✅ |
| `403` | `not_managed` | Object is not managed ✅ |
| `403` | `reserved_name` | `pmss-*`, `role_security_manager` ✅ |
| `404` | `not_found` | Object does not exist |
| `409` | `already_exists` | Object with this name already exists |
| `409` | `certificate_client` | `POST /api/v1/clients/{username}/password` for a `CN=` client ✅. When creating with a password: `422 validation_failed`. PMSS also uses the code for `enable`/`disable` of a `CN=` client (outside the specification, section 4) |
| `412` | `precondition_failed` | `If-Match` does not match ✅ |
| `413` | `payload_too_large` | Body too large |
| `422` | `validation_failed` | Invalid fields, password, ACL, name, prefix missing ✅ |
| `422` | `unknown_role` / `unknown_group` | Assignment to a non-existent or unmanaged role or group ✅ |
| `428` | `precondition_required` | `If-Match` missing ✅ |
| `500` | `readback_mismatch` | After `modifyRole`, the state read back deviates ✅ |
| `502` | `broker_error` | DynSec reports an error that does not match any other code |
| `502` | `partial_failure` | Compensation failed, object exists half-created ✅ |
| `503` | `broker_unavailable` | No connection to the broker; **the command was not sent** ✅ S-13 |
| `504` | `broker_timeout` | No response from the broker within the timeout; **the state is unknown**, the change may have been executed (section 3.7) ✅ S-13 |

TasmoFleet handles at least: `401` (exchange token again), `403` (do not offer the function), `412` (read again, present the diff for approval again), `422` (show the error), `503` (try again later), `504` (read again, section 3.7) and the remaining `5xx` (abort, mark nothing as done).

### 3.6 Warnings

✅ S-12

Responses to modifying calls with a body can contain a field `warnings` (list with `code`, `pointer`, `detail`; empty as `[]`). A warning does not prevent the change. So far there is one case (✅ PMSS 7.3): a deny rule without a higher priority than an allow rule of the same type in the same role.

```json
"warnings": [
  {
    "code": "deny_priority_not_higher",
    "pointer": "/acls/1",
    "detail": "Deny rule for 'stat/+/FILEDOWNLOAD' has priority 0, same as allow rule 'stat/#'; evaluation order is undefined."
  }
]
```

TasmoFleet shows warnings during approval.

### 3.7 Unreachable broker and unclear state

✅ S-13

The service sends changes as DynSec commands via MQTT. If the connection breaks after a command has reached the broker, the response can be lost even though the broker has executed the command. DynSec commands are not idempotent: a repetition executes them a second time and then reports e.g. `already_exists` (PMSS 7.2, A-9).

**Rules for the service:**

- `503 broker_unavailable` only if the command was **not** sent to the broker. The service does not send it later either.
- If the response does not arrive after sending, the service reads the affected object back before it responds:
  - If the actual state matches the target of the request, it responds as on success (`200`, `201`, `204`).
  - If the state cannot be determined or does not match the target, it responds with `504 broker_timeout`.
- The service does not repeat modifying commands on its own.
- A password change cannot be read back, because DynSec does not provide a password hash (S-5). If the response to `POST …/password` does not arrive, the service always responds with `504`. When creating a client with a generated password, reading back the client is sufficient: the service knows the password it sent and returns it with `201`.

**Rules for TasmoFleet:**

- With `503`, nothing has changed. TasmoFleet may send the request again unchanged later.
- With `504`, the change counts neither as done nor as failed. TasmoFleet does not repeat the request blindly, but reads the actual state again (`GET /api/v1/export` or the single object), rebuilds the diff and presents it for approval again if there are deviations.
- With `504` on a password change, the previous password counts as possibly invalid. TasmoFleet requests a new password again (the ETag is unchanged, S-5) and transfers it to the device. The rule "one running password change per client" (section 4.4) remains in force until then.
- The audit of approvals (D-51) records a `504` as an unclear outcome.

Example:

```http
HTTP/1.1 504 Gateway Timeout
Content-Type: application/problem+json
```

```json
{
  "title": "Broker did not answer in time; state unknown",
  "status": 504,
  "code": "broker_timeout",
  "detail": "No response to setClientPassword for 'wz-steckdose-tv'. The password may or may not have been changed.",
  "instance": "/api/v1/clients/wz-steckdose-tv/password"
}
```

## 4. Endpoints for TasmoFleet

TasmoFleet needs only the following endpoints. The other endpoints of PMSS v1 (lists, single ACLs via `POST`/`DELETE`, `PATCH` of the text name, `enable`/`disable`) remain allowed, but are not part of the specification. In the OpenAPI file they carry the tag `pmss-extra` (section 7.1).

| Method | Endpoint | Scope | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/info` | `read` | Version, prefixes, marker, password rule ✅ S-2 |
| `GET` | `/api/v1/export` | `read` | Actual state of all managed objects |
| `GET` | `/api/v1/clients/{username}` | `read` | One client with `ETag` |
| `POST` | `/api/v1/clients` | `write` | Create client, optionally with roles, groups, password |
| `POST` | `/api/v1/clients/{username}/password` | `write` | New password |
| `DELETE` | `/api/v1/clients/{username}` | `write` | Delete client (also: block) |
| `POST` | `/api/v1/clients/{username}/roles` | `write` | Assign role |
| `DELETE` | `/api/v1/clients/{username}/roles/{role}` | `write` | Remove role |
| `GET` | `/api/v1/groups/{group}` | `read` | One group with `ETag` |
| `POST` | `/api/v1/groups` | `write` | Create group |
| `DELETE` | `/api/v1/groups/{group}` | `write` | Delete group |
| `POST` | `/api/v1/groups/{group}/clients` | `write` | Add client to group |
| `DELETE` | `/api/v1/groups/{group}/clients/{username}` | `write` | Remove client from group |
| `POST` | `/api/v1/groups/{group}/roles` | `write` | Assign role to group |
| `DELETE` | `/api/v1/groups/{group}/roles/{role}` | `write` | Remove role from group |
| `GET` | `/api/v1/roles/{role}` | `read` | One role with ACLs and `ETag` |
| `POST` | `/api/v1/roles` | `write` | Create role, optionally with ACLs ✅ S-6 |
| `PUT` | `/api/v1/roles/{role}/acls` | `write` | Replace the ACL list completely |
| `DELETE` | `/api/v1/roles/{role}` | `write` | Delete role |

`enable`/`disable` are deliberately not in the specification: `disableClient` does not block a certificate login (✅ PMSS 5.2). TasmoFleet blocks a client with `DELETE`. PMSS rejects `enable`/`disable` for `CN=` clients with `409 certificate_client`, without sending a command to the broker (✅ PMSS 7.3, variant A).

### 4.1 `GET /api/v1/info`

✅ S-2: Required endpoint, scope `read`. It lets TasmoFleet recognise which service and which marker it is working with, without hard-coding these values. Prefix and marker are configurable in PMSS (✅ PMSS 6.4).

```http
GET /api/v1/info
Authorization: Bearer <token>
```

```json
{
  "apiVersion": "1.1",
  "implementation": {
    "name": "phylax-mqtt-security-service",
    "version": "0.1.0"
  },
  "broker": {
    "product": "mosquitto",
    "version": "2.1.2"
  },
  "managed": {
    "rolePrefix": "tf_",
    "groupPrefix": "tf_",
    "clientMarker": "managed-by: pmss"
  },
  "passwordPolicy": {
    "length": 24,
    "alphabet": "A-Za-z0-9"
  },
  "reservedNames": ["pmss-*", "role_security_manager"],
  "limits": {
    "maxRequestBytes": 1048576
  }
}
```

| Field | Meaning |
|---|---|
| `apiVersion` | Version of this specification, `MAJOR.MINOR` |
| `implementation` | Name and version of the implementation; for display only |
| `broker` | Product and version of the broker; for display only |
| `managed.rolePrefix`, `managed.groupPrefix` | Prefix that new roles or groups must carry |
| `managed.clientMarker` | Content of `textdescription` of managed clients |
| `passwordPolicy` | Length and alphabet of the passwords |
| `reservedNames` | Reserved names; `*` stands for any characters |
| `limits.maxRequestBytes` | Largest allowed request body in bytes, at least 1048576 (1 MiB) ✅ S-11 |

Rules for TasmoFleet:

- Read `GET /api/v1/info` before the first export of a session.
- If the major version of `apiVersion` is not `1`, offer no changes and show the error.
- Name new roles and groups with the prefixes from `managed`; check Tasmota topics against `reservedNames` (overview 12).
- Check a supplied password against `passwordPolicy` before sending.

### 4.2 `GET /api/v1/export`

✅ D-43: all managed objects, with `etag` per object. Unmanaged objects (admins, an existing shared user such as `legacy-shared-user`, `role_legacy`) are not included. Structure ✅ S-3:

```http
GET /api/v1/export
Authorization: Bearer <token>
```

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
```

```json
{
  "exportedAt": "2026-11-20T21:30:12Z",
  "apiVersion": "1.1",
  "clients": [
    {
      "username": "CN=homeassistant,O=mqtt-apps",
      "textname": "Home Assistant",
      "textdescription": "managed-by: pmss",
      "authType": "certificate",
      "disabled": false,
      "roles": [
        { "rolename": "tf_role_homeassistant", "priority": -1 }
      ],
      "groups": [],
      "etag": "\"c-41d0e8c2\""
    },
    {
      "username": "wz-steckdose-tv",
      "textname": "Wohnzimmer Steckdose TV",
      "textdescription": "managed-by: pmss",
      "authType": "password",
      "disabled": false,
      "roles": [
        { "rolename": "tf_role_dev_a4cf12345678", "priority": -1 }
      ],
      "groups": [
        { "groupname": "tf_group_tasmota", "priority": -1 }
      ],
      "etag": "\"c-9f3b2a71\""
    }
  ],
  "groups": [
    {
      "groupname": "tf_group_tasmota",
      "textname": "Tasmota-Geräte",
      "roles": [
        { "rolename": "tf_role_tasmota", "priority": -1 }
      ],
      "clients": [
        { "username": "wz-steckdose-tv" }
      ],
      "etag": "\"g-0a77c315\""
    }
  ],
  "roles": [
    {
      "rolename": "tf_role_dev_a4cf12345678",
      "textname": "Gerät wz-steckdose-tv: GroupTopics, FallbackTopic, Discovery",
      "acls": [
        { "acltype": "publishClientReceive", "topic": "cmnd/a4cf12345678_fb/#", "allow": true, "priority": 0 },
        { "acltype": "publishClientReceive", "topic": "cmnd/wohnzimmer/#",      "allow": true, "priority": 0 },
        { "acltype": "publishClientSend",    "topic": "tasmota/discovery/A4CF12345678/#", "allow": true, "priority": 0 },
        { "acltype": "subscribePattern",     "topic": "cmnd/a4cf12345678_fb/#", "allow": true, "priority": 0 },
        { "acltype": "subscribePattern",     "topic": "cmnd/wohnzimmer/#",      "allow": true, "priority": 0 }
      ],
      "etag": "\"r-e2b6a019\""
    },
    {
      "rolename": "tf_role_homeassistant",
      "textname": "Home Assistant",
      "acls": [
        { "acltype": "publishClientReceive", "topic": "stat/#",               "allow": true,  "priority": 0 },
        { "acltype": "publishClientReceive", "topic": "stat/+/FILEDOWNLOAD",  "allow": false, "priority": 10 },
        { "acltype": "publishClientReceive", "topic": "tele/#",               "allow": true,  "priority": 0 },
        { "acltype": "publishClientSend",    "topic": "cmnd/wz-steckdose-tv/POWER", "allow": true, "priority": 0 },
        { "acltype": "subscribePattern",     "topic": "stat/#",               "allow": true,  "priority": 0 },
        { "acltype": "subscribePattern",     "topic": "tele/#",               "allow": true,  "priority": 0 }
      ],
      "etag": "\"r-77f0c3aa\""
    },
    {
      "rolename": "tf_role_tasmota",
      "textname": "Tasmota-Grundprofil",
      "acls": [
        { "acltype": "publishClientReceive", "topic": "cmnd/%u/#", "allow": true, "priority": 0 },
        { "acltype": "publishClientSend",    "topic": "stat/%u/#", "allow": true, "priority": 0 },
        { "acltype": "publishClientSend",    "topic": "tele/%u/#", "allow": true, "priority": 0 },
        { "acltype": "subscribePattern",     "topic": "cmnd/%u/#", "allow": true, "priority": 0 }
      ],
      "etag": "\"r-5c1e9d40\""
    }
  ]
}
```

**Fields** ✅ S-3:

| Object | Fields |
|---|---|
| Export | `exportedAt`, `apiVersion`, `clients`, `groups`, `roles` |
| Client | `username`, `textname`, `textdescription`, `authType`, `disabled`, `roles`, `groups`, `etag` |
| Group | `groupname`, `textname`, `roles`, `clients`, `etag` |
| Role | `rolename`, `textname`, `acls`, `etag` |
| Assignment | `rolename` or `groupname` with `priority`; clients of a group only `username` |
| ACL | `acltype`, `topic`, `allow`, `priority` |

- All fields are always present. Empty lists are delivered as `[]`, missing text as `""`.
- `priority` is always present, also with the default value (assignment −1, ACL 0).
- The service derives `authType` from the name: `CN=…` → `certificate`, otherwise `password`.

**Sorting and comparison** ✅ S-3:

- The service sorts so that two exports of the same state look the same and can be compared line by line:
  - `clients` by `username`, `groups` by `groupname`, `roles` by `rolename`,
  - assignments by role, group or user name,
  - `acls` by `acltype`, then by `topic`.
- Sorting is by Unicode code points, without regard to upper and lower case or language (e.g. `CN=…` before `wz-…`, `stat/#` before `stat/+/…`).
- The order has **no meaning**. TasmoFleet compares target and actual state via keys, not via positions:

| Element | Key |
|---|---|
| Client | `username` |
| Group | `groupname` |
| Role | `rolename` |
| ACL within a role | `acltype` + `topic` |
| Assignment | Name of the assigned role, group or client |

- In requests (`PUT …/acls`, `POST /api/v1/roles`) the order has no meaning either. Single objects (`GET /api/v1/roles/{role}` etc.) have the same structure and the same sorting as in the export.
- If an object disappears from the export because its marker or prefix was removed via break-glass, the drift report shows it as missing. TasmoFleet does not recreate it automatically.

Further notes:

- **Role per Tasmota device** ✅ S-7: GroupTopic, FallbackTopic and discovery do not fit the scheme with `%u` (overview section 4, D-53). They are placed in a separate role per device:
  - Name `tf_role_dev_<mac>`, `<mac>` = MAC in lower case, 12 hex characters without separators, e.g. `tf_role_dev_a4cf12345678`.
  - `textname` contains the topic, e.g. `Gerät wz-steckdose-tv: GroupTopics, FallbackTopic, Discovery`.
  - Reason: the MAC is unique, has a fixed length and no special characters; FallbackTopic and discovery depend on it anyway. If the topic changes, a new client is created (user name = topic, D-15), the device role stays and is assigned to the new client.
  - Topics in the ACLs keep their spelling, e.g. `tasmota/discovery/A4CF12345678/#` in upper case.
- The export is the backup that TasmoFleet stores before applying. ✅ D-43

### 4.3 `POST /api/v1/clients` – create client

✅ PMSS 7.3/7.4: roles and groups optional, password optional. The marker `managed-by: pmss` is set; the caller cannot set `textdescription`.

**Request – let the service generate the password (normal case):**

```http
POST /api/v1/clients
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "username": "wz-steckdose-tv",
  "textname": "Wohnzimmer Steckdose TV",
  "groups": [
    { "groupname": "tf_group_tasmota" }
  ],
  "roles": [
    { "rolename": "tf_role_dev_a4cf12345678" }
  ]
}
```

**Response:**

```http
HTTP/1.1 201 Created
Location: /api/v1/clients/wz-steckdose-tv
ETag: "c-9f3b2a71"
Cache-Control: no-store
Content-Type: application/json; charset=utf-8
```

```json
{
  "client": {
    "username": "wz-steckdose-tv",
    "textname": "Wohnzimmer Steckdose TV",
    "textdescription": "managed-by: pmss",
    "authType": "password",
    "disabled": false,
    "roles": [ { "rolename": "tf_role_dev_a4cf12345678", "priority": -1 } ],
    "groups": [ { "groupname": "tf_group_tasmota", "priority": -1 } ]
  },
  "password": "Q7mXr2Lk9pTz4WbN8cVd3HsF",
  "passwordGenerated": true
}
```

**Request – supply a password:** as above, additionally `"password": "<24 Zeichen>"`. The response then contains **no** password and `"passwordGenerated": false`. ✅ S-12

**Request – certificate client ("TLS required"):**

```json
{
  "username": "CN=homeassistant,O=mqtt-apps",
  "textname": "Home Assistant",
  "roles": [ { "rolename": "tf_role_homeassistant" } ]
}
```

Response without `password`. A supplied password is rejected with `422`. ✅

**Errors:**

| Case | Response |
|---|---|
| Name `pmss-…` | `403 reserved_name` |
| Password client with `=` or `,` in the name | `422 validation_failed` |
| Password with `;`, space or a different length | `422 validation_failed` |
| Client already exists | `409 already_exists` |
| Role does not exist or is not managed (e.g. `role_legacy`) | `422 unknown_role`; the client is deleted again ✅ |
| Deleting again failed | `502 partial_failure` with `"clientExists": true` ✅ |
| No response from the broker, state cannot be determined | `504 broker_timeout` (section 3.7) ✅ S-13 |

Example of the compensation path:

```json
{
  "type": "https://pmss.example.org/errors/unknown_role",
  "title": "Unknown or unmanaged role",
  "status": 422,
  "code": "unknown_role",
  "detail": "Role 'tf_role_dev_a4cf12345678' does not exist. The client was created and deleted again.",
  "compensated": true,
  "clientExists": false
}
```

### 4.4 `POST /api/v1/clients/{username}/password` – new password

```http
POST /api/v1/clients/wz-steckdose-tv/password
Authorization: Bearer <token>
If-Match: "c-9f3b2a71"
Content-Type: application/json
```

```json
{}
```

Empty body: the service generates the password. With `{"password": "<24 Zeichen>"}` the supplied one is set.

```http
HTTP/1.1 200 OK
ETag: "c-9f3b2a71"
Cache-Control: no-store
```

```json
{
  "username": "wz-steckdose-tv",
  "password": "h3RtY8vQm2NpXc6KzL4bWs9D",
  "passwordGenerated": true
}
```

**ETag on password change** ✅ S-5: A password change does not change the ETag, because the password hash is not part of the ETag. DynSec does not provide the hash via `getClient` either; the output is the same before and after the password change (tested 21.11.2026 with Mosquitto 2.1.2).

> **Consequence for TasmoFleet: only one password change per client at a time**
> `If-Match` does not prevent two users from requesting a new password for the same client at the same time. Both calls would succeed, and the device might receive the password generated first, which has already been overwritten. TasmoFleet therefore allows only one running password change per client: from the request until the confirmed transfer via `Backlog` or until the abort.

**Without a response from the broker** ✅ S-13: Because a password change cannot be read back, the service always responds with `504 broker_timeout` in this case. TasmoFleet then requests a new password again and transfers it (section 3.7).

`CN=` client → `409 certificate_client`. Unmanaged client → `403 not_managed`.

### 4.5 `DELETE /api/v1/clients/{username}` – delete or block

```http
DELETE /api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps
Authorization: Bearer <token>
If-Match: "c-41d0e8c2"
```

```http
HTTP/1.1 204 No Content
```

The broker closes an open connection of the client. ✅ PMSS 5.2

> **Rule for TasmoFleet: do not reuse blocked names**
> DynSec only knows the name, not the certificate. If the same name is created again after blocking because of a compromise, the old certificate is valid again. Successors get a sequential number, e.g. `CN=homeassistant-2,O=mqtt-apps`. ✅ D-40, SEC-23. The service does not know deleted names; TasmoFleet has to remember them.

### 4.6 Assigning and removing roles

Example: Home Assistant additionally gets the role `tf_role_mqtt_viewer`.

```http
POST /api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps/roles
Authorization: Bearer <token>
If-Match: "c-41d0e8c2"
Content-Type: application/json
```

```json
{ "rolename": "tf_role_mqtt_viewer", "priority": -1 }
```

`priority` is optional, default −1 as in DynSec. ✅

```http
HTTP/1.1 200 OK
ETag: "c-6a2d91f0"
```

✅ S-10: The response body is the changed client as in `GET /api/v1/clients/{username}`, with `warnings`. `DELETE` responds with `204` and the new `ETag` header.

Removing:

```http
DELETE /api/v1/clients/CN%3Dhomeassistant%2CO%3Dmqtt-apps/roles/tf_role_mqtt_viewer
Authorization: Bearer <token>
If-Match: "c-6a2d91f0"
```

```http
HTTP/1.1 204 No Content
ETag: "c-41d0e8c2"
```

The ETag is a hash over the state: after removing, it is the same as before again.

The group endpoints (`/api/v1/groups/{group}/clients`, `/api/v1/groups/{group}/roles`) work the same way, with `{"username": "…"}` or `{"rolename": "…", "priority": -1}` and the `ETag` of the group. Only the ETag of the group changes (S-4). `POST` returns the changed group as in `GET /api/v1/groups/{group}` (S-10).

### 4.7 `POST /api/v1/roles` – create role

Prefix from `GET /api/v1/info` (`tf_`) required, otherwise `422`. ✅

✅ S-6: The ACL list can be supplied right away, so that the role is created completely in one step. `acls` is optional; without ACLs, an empty role is created that grants no permissions because of default deny.

Procedure in the service:

1. Check every entry as with `PUT …/acls` (section 4.8); on errors `422`, without a command to the broker.
2. Send `createRole` with the complete list (one command).
3. Read the role back via `getRole` and compare it with the list sent.
4. On deviation, delete the role again (`deleteRole`) and report `500 readback_mismatch` with `"compensated": true`. If deleting fails, `502 partial_failure` with `"roleExists": true`.

```http
POST /api/v1/roles
Authorization: Bearer <token>
Content-Type: application/json
```

```json
{
  "rolename": "tf_role_dev_a4cf12345678",
  "textname": "Gerät wz-steckdose-tv: GroupTopics, FallbackTopic, Discovery",
  "acls": [
    { "acltype": "subscribePattern",     "topic": "cmnd/wohnzimmer/#", "allow": true },
    { "acltype": "publishClientReceive", "topic": "cmnd/wohnzimmer/#", "allow": true }
  ]
}
```

```http
HTTP/1.1 201 Created
Location: /api/v1/roles/tf_role_dev_a4cf12345678
ETag: "r-3d9a0b17"
```

Response body: the role as in `GET /api/v1/roles/{role}`, sorted, with `warnings` (section 3.6).

| Case | Response |
|---|---|
| Prefix missing | `422 validation_failed` |
| ACL invalid (missing `allow`, unknown `acltype`, duplicate combination) | `422 validation_failed` |
| Role already exists | `409 already_exists` |
| State read back deviates | `500 readback_mismatch`, role deleted again |
| Deleting again failed | `502 partial_failure` with `"roleExists": true` |
| No response from the broker, state cannot be determined | `504 broker_timeout` (section 3.7) |

### 4.8 `PUT /api/v1/roles/{role}/acls` – replace the ACL list

✅ D-45: replaces the complete list in one step (`modifyRole`), then the service reads the role back and compares.

ACL fields ✅ (PMSS 7.3):

| Field | Rule |
|---|---|
| `acltype` | Required: `publishClientSend`, `publishClientReceive`, `subscribeLiteral`, `subscribePattern`, `unsubscribeLiteral`, `unsubscribePattern` |
| `topic` | Required; unique in the role together with `acltype` |
| `allow` | **Required, no default value** |
| `priority` | Optional, default 0, −100000 to 100000 |

```http
PUT /api/v1/roles/tf_role_homeassistant/acls
Authorization: Bearer <token>
If-Match: "r-77f0c3aa"
Content-Type: application/json
```

```json
{
  "acls": [
    { "acltype": "subscribePattern",     "topic": "stat/#",              "allow": true },
    { "acltype": "publishClientReceive", "topic": "stat/#",              "allow": true },
    { "acltype": "publishClientReceive", "topic": "stat/+/FILEDOWNLOAD", "allow": false, "priority": 10 },
    { "acltype": "subscribePattern",     "topic": "tele/#",              "allow": true },
    { "acltype": "publishClientReceive", "topic": "tele/#",              "allow": true }
  ]
}
```

```http
HTTP/1.1 200 OK
ETag: "r-c09e5f28"
Content-Type: application/json; charset=utf-8
```

```json
{
  "rolename": "tf_role_homeassistant",
  "textname": "Home Assistant",
  "acls": [
    { "acltype": "publishClientReceive", "topic": "stat/#",              "allow": true,  "priority": 0 },
    { "acltype": "publishClientReceive", "topic": "stat/+/FILEDOWNLOAD", "allow": false, "priority": 10 },
    { "acltype": "publishClientReceive", "topic": "tele/#",              "allow": true,  "priority": 0 },
    { "acltype": "subscribePattern",     "topic": "stat/#",              "allow": true,  "priority": 0 },
    { "acltype": "subscribePattern",     "topic": "tele/#",              "allow": true,  "priority": 0 }
  ],
  "etag": "\"r-c09e5f28\"",
  "warnings": []
}
```

With `"priority": 0` on the FILEDOWNLOAD rule, the response would also be `200`, but with the warning `deny_priority_not_higher` (section 3.6).

**Errors:** missing `allow`, unknown `acltype`, duplicate combination of `acltype` + `topic` → `422`, before a command goes to the broker ✅. Outdated `If-Match` → `412` ✅. Deviation when reading back → `500 readback_mismatch` ✅. No response from the broker and state cannot be determined → `504 broker_timeout` (section 3.7) ✅ S-13.

## 5. Procedure: switching a Tasmota device over to its own credentials

```
security-admin        TasmoFleet                         Security Service         Device
     │                    │                                     │                    │
     │  Start switch-over │                                     │                    │
     │───────────────────►│ token exchange (OIDC provider)      │                    │
     │                    │ scope contains write? else abort    │                    │
     │                    │ GET /api/v1/export ────────────────►│                    │
     │                    │◄───────────────── actual + ETags ───│                    │
     │                    │ store export (backup)               │                    │
     │                    │ derive target from Tasmota data     │                    │
     │                    │ (topic, GroupTopic1–4, fallback, MAC)                    │
     │◄── diff + warnings │                                     │                    │
     │─── approval ──────►│ audit of approval (TasmoFleet)      │                    │
     │                    │ POST /api/v1/roles (device role) ──►│                    │
     │                    │ POST /api/v1/clients ──────────────►│                    │
     │                    │◄────────────── 201 + password ──────│                    │
     │                    │ Backlog MqttUser …; MqttPassword … ─────────────────────►│
     │                    │ discard password                    │                    │ reconnect
     │                    │ check connection and permissions    │                    │
     │                    │ failure → fallback via HTTP API ────────────────────────►│
```

Preconditions that TasmoFleet checks before the first call (✅ overview 6.2, 12):

- [ ] TasmoFleet runs in OIDC mode, the user is logged in via OIDC (section 2.2).
- [ ] Topic does not start with `pmss-` and contains neither `=` nor `,`.
- [ ] All four GroupTopics have been read (#1005).
- [ ] The device's HTTP API is reachable (`SetOption128` not `1`), otherwise block or warn.
- [ ] Exchanged token contains `write`.

If a step responds with `504 broker_timeout`, TasmoFleet aborts the procedure, reads the export again and presents the new diff for approval (section 3.7). The device only gets credentials via `Backlog` once the client has definitely been created and TasmoFleet has a password for it.

## 6. Tasks of TasmoFleet

| Task | |
|---|---|
| Target state, diff against export, approval by `security-admin` | ✅ D-43 |
| Own audit of approvals, readable for `admin` and `security-admin` | ✅ D-51 |
| Store the export before applying | ✅ |
| Drift report (target against export, without applying) | ✅ |
| `If-Match` on every change; on `412` read again and have it approved again | ✅ |
| On `504` do not repeat blindly, but read again; on a password change request a new password | ✅ S-13 |
| Keep the password only until the successful transfer or until the abort | ✅ D-54 (overview, question 15) |
| Remember blocked names and subjects, number successors | ✅ D-40 |
| Only one running password change per client | ✅ S-5 |
| Compare group membership via the group | ✅ S-4 |
| Name device roles `tf_role_dev_<mac>` | ✅ S-7 |
| Show warnings during approval | ✅ S-12 |
| Request `write` only for `security-admin`, if rejected once `read` only, evaluate `scope` of the exchanged token | ✅ S-16 |
| Offer only in OIDC mode; exchange a valid session token; call the token endpoint via the public URL | ✅ S-17 |

TasmoFleet does **not**: act on the broker as DynSec admin, publish on `$CONTROL/dynamic-security/#`, change unmanaged objects, call with a service account with `write`.

## 7. Versioning

✅ S-9

- All paths carry the major version: `/api/v1/…`. The exception is `/healthz` (internal, without token).
- `GET /api/v1/info` provides the exact version (`apiVersion`, `MAJOR.MINOR`).
- Within 1.x only backward-compatible changes: new optional fields, new endpoints, new `code` values, new warnings. TasmoFleet ignores unknown fields in responses and treats unknown `code` values according to the status (section 3.4).
- An incompatible change gets `/api/v2/…`. An implementation can offer v1 and v2 in parallel for a while.

### 7.1 Machine-readable version (OpenAPI)

✅ S-14

- The specification is also available as **`api/openapi.yaml`** (OpenAPI 3.2.1) in the PMSS repository. It describes paths, scopes, headers (`ETag`, `If-Match`, `Location`, `Cache-Control`, `WWW-Authenticate`), request and response schemas and the error codes per status from section 3.5.
- **This document remains authoritative.** A contradiction between the two is an error in the OpenAPI file and is fixed there. Behaviour that cannot be expressed as a schema (ETag rules 3.2, unclear state 3.7, compensation path 4.3 and 4.7) is described only briefly in the OpenAPI file, with a reference to this document.
- `info.version` of the OpenAPI file corresponds to `apiVersion` (section 4.1); `x-specification-version` names the version of this document.
- **Security scheme `oidc` of type `oauth2`** with the scopes `read` and `write`. The service only checks the bearer token (section 2.1); how it was obtained does not matter to it. The addresses of the flows are placeholders, because they depend on the provider. The flows describe the paths from the PMSS document (7.5):
  - `deviceAuthorization` (RFC 8628, from OpenAPI 3.2): administrators, login and second factor in the browser.
  - `clientCredentials`: scripts and monitoring, in production `read` only (SEC-35); `write` only in test environments.
  - The TasmoFleet token exchange (section 2.2) has no flow object of its own in OpenAPI and is therefore only described as text in the description of the scheme.
  - There is no browser login flow (`authorizationCode`); the service has no user interface.
- Endpoints of an implementation that are not in the specification carry the tag `pmss-extra` (`kind: badge`) and `x-pmss-extra: true`. TasmoFleet can hide them when generating a client.
- The error codes are listed per status in the file. For TasmoFleet, section 3.4 still applies: new codes can be added within 1.x and are treated according to the status.
- PMSS checks in CI that the operations of the file correspond exactly to the routes of the service and that every response recorded in the tests matches the file: status, required headers, body and error code (`test/openapi/check.py`).
- Tools that do not yet know OpenAPI 3.2 may reject the file. 3.2 is backward compatible with 3.1; with the security scheme `deviceAuthorization`, however, the file uses a feature that only exists from 3.2.

## 8. Decisions of this specification

| No. | Decision | Section |
|---|---|---|
| S-1 | Errors as `application/problem+json` according to RFC 9457; `status` and `code` are binding, not `type` | 3.4, 3.5 |
| S-2 | `GET /api/v1/info` is required, scope `read` | 4.1 |
| S-3 | Export with three sorted lists, `etag` per object, `authType`; comparison via keys, not via the order | 4.2 |
| S-4 | Every relationship has one owner; `If-Match` and new ETag only for the object in the path | 3.2 |
| S-5 | A password change does not change the ETag; TasmoFleet allows only one running password change per client | 4.4 |
| S-6 | `POST /api/v1/roles` with ACLs, check, read-back and compensation path | 4.7 |
| S-7 | The role per Tasmota device is named `tf_role_dev_<mac>` | 4.2 |
| S-8 | DynSec field names unchanged, own fields in camelCase | 1 |
| S-9 | All paths with major version `/api/v1/…`, `/healthz` without version | 7 |
| S-10 | Assignment via `POST` returns `200` with the changed object, `DELETE` `204` with `ETag` | 4.6 |
| S-11 | Request body at least 1 MiB, limit in `GET /api/v1/info` | 3.1, 4.1 |
| S-12 | Configuration in TasmoFleet, timestamps RFC 3339 UTC, URL-encoded path parameters, warnings, no return of a supplied password | 2.2, 3.1, 3.6, 4.3 |
| S-13 | `504 broker_timeout` = state unknown; the service reads back beforehand, TasmoFleet reads again instead of repeating blindly | 3.5, 3.7 |
| S-14 | `api/openapi.yaml` (OpenAPI 3.2.1) as machine-readable version; this document remains authoritative | 7.1 |
| S-15 | No specific identity provider: OIDC provider with token exchange according to RFC 8693 and the properties from 2.3; access token with `scope` claim required | 1, 2.1, 2.3 |
| S-16 | Request `write` only for `security-admin`; if rejected, once `read` only; always evaluate `scope` of the exchanged token | 2.2 |
| S-17 | Security Manager only in OIDC mode; exchange a valid session token; token endpoint via the same public URL as the login | 2.2, 5 |

## References

- Architecture overview `mqtt-security-overview` (current version), sections 4, 5.4, 7.2, 7.3, 11 (D-52, D-53), 12
- PMSS detail document `phylax-mqtt-security-service-design` (current version), sections 5.2, 6.4, 7.2–7.5 (A-9), 7.9
- PMSS, OpenAPI file: https://github.com/Noschvie/phylax-mqtt-security-service/blob/main/api/openapi.yaml, check `test/openapi/check.py`
- PMSS, token checks of the providers: `test/integration/keycloak/check_tokens.py`, `test/integration/authentik/check_tokens.py`
- `mqtt-acl-verify`: `tests/test_dynsec_control.py`, `probes/autopaho-reconnect/` – tests for `correlationData`, `getClient` and reconnect: https://github.com/Noschvie/mqtt-acl-verify
- Mosquitto Dynamic Security plugin: https://mosquitto.org/documentation/dynamic-security/
- Keycloak – token exchange: https://www.keycloak.org/securing-apps/token-exchange
- authentik – token exchange: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/token_exchange/
- OpenAPI Specification 3.2.1: https://spec.openapis.org/oas/v3.2.1.html
- RFC 8628 – OAuth 2.0 Device Authorization Grant: https://www.rfc-editor.org/rfc/rfc8628
- RFC 8693 – OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
- RFC 9457 – Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc9457
- RFC 6901 – JSON Pointer: https://www.rfc-editor.org/rfc/rfc6901
- RFC 6750 – Bearer Token Usage: https://www.rfc-editor.org/rfc/rfc6750
- RFC 9110 – HTTP Semantics (`ETag`, `If-Match`, `412`): https://www.rfc-editor.org/rfc/rfc9110
- RFC 6585 – `428 Precondition Required`: https://www.rfc-editor.org/rfc/rfc6585
