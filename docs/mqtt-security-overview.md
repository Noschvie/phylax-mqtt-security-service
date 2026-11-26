# MQTT Security Management – TasmoFleet and PMSS
## Architecture Overview – Draft for Review

**Status:** Draft – for technical review  
**Version:** 1.1  
**Date:** 25 November 2026  
**Detail document:** `phylax-mqtt-security-service-design` (current version)  
**Interface specification:** `mqtt-security-service-api-v1` ("MQTT Security Service API v1", current version)  
**Identity provider:** OIDC provider with token exchange; tested with Keycloak 26.8.2 and authentik 2026.8.6, at least Keycloak 26.2 or authentik 2026.8.3

> **Note on names and environment**
> This document describes the architecture in general terms. Names of hosts, users and domains are placeholders: `legacy-shared-user` for the existing shared user, `mqtt.example.org` for the broker name of the TLS listeners. The details of the concrete environment (hosts, paths, networks, inventory, migration status) are in a separate, non-public operations document.

---

> **Test results of 20 November 2026**
> Tested with `mqtt-acl-verify` against **Mosquitto 2.1.2** with Dynamic Security (test broker `testbroker-dynsec/`, CI on amd64 and arm64 as well as Mosquitto 2.1.2 built from source). Details in the PMSS document and in `docs/testbroker-dynsec.md`.
> 1. **Permissions as with Classic ACL:** The existing 11 cases also pass with DynSec, including the deny for FILEDOWNLOAD via priority. ✅
> 2. **`dynsec init` gives the admin read access to `#`.** The role `admin` is therefore replaced by `role_security_manager` and deleted.
> 3. **Deny-by-default must be set explicitly:** `publishClientReceive` is allowed after `init`.
> 4. **Placeholders `%u`/`%c` in DynSec only from 2.1.**
> 5. **Admin only via certificate (`use_identity_as_username`):** The admin is rejected on all other listeners. With a password it would also be accepted on 1883.
> 6. **`disableClient` does not block a certificate login:** The client keeps its permissions. Blocking is done with `deleteClient`.
> 7. **App certificates with `use_subject_as_username`:** An app certificate with `CN=pmss-admin` becomes `CN=pmss-admin,O=mqtt-apps` and gets no admin permissions.
> 8. **A listener cannot mix certificate and password:** separate listeners are required.
> 9. **Password hashes can be taken over:** DynSec stores the same `$7$` format as `pwfile`. The existing password stays valid.
> 10. **`mosquitto_ctrl` exits with code 0 even on "Not authorized".** Scripts check the output.

> **Test results of the identity providers (21 and 24 November 2026)**
> The tests check what the provider writes into the tokens; PMSS is not involved yet. Details in the PMSS document, section 7.9.
> - **Keycloak 26.8.2** (`test/integration/keycloak`, 10 of 10): `write` only for `security-admin`, token exchange with `aud` = PMSS and `sub` = user, foreign tokens cannot be exchanged. ✅
> - **authentik 2026.8.6** (`test/integration/authentik`, 16 of 16): the same properties. ✅ Differences: `write` without `security-admin` rejects the whole request, no `typ` claim, `azp` is PMSS, the issuer follows the host name of the request.

> **Carried over from v0.2 (19 November 2026)**
> Mosquitto Classic ACL supports deny rules (`topic deny <topic>`), which take precedence over read/write. Relevant for the initial state before the migration.

---

## 1. Goal

The existing Mosquitto management via `password_file` and optionally `acl_file` is replaced step by step by the built-in Mosquitto Dynamic Security plugin (DynSec).

User and permission management is first done directly with `mosquitto_ctrl`. After that it is taken over by the **Phylax MQTT Security Service (PMSS)**, a Go application with a REST API that talks to the broker internally via MQTT.

**TasmoFleet** gets a Security Manager that administrators use to manage MQTT clients, profiles and credentials. TasmoFleet does not apply these changes to the broker itself, but through the PMSS REST API.

Initial situation: A shared MQTT user (in this document `legacy-shared-user`) is used by several Tasmota devices and applications. A client can therefore read or write topics of other clients. Configuration data, credentials, and backup and restore content need particular protection.

**Principles:**

- The broker remains an independent infrastructure component.
- TasmoFleet manages, but operates neither the broker nor the DynSec admin.
- Deny-by-default: anything not allowed in a profile or an exception is forbidden.
- The first migration is deliberately kept small: the existing shared user is taken over with its current password and compatible permissions and restricted step by step afterwards.

## 2. Scope: all MQTT clients

The concept applies to physical devices as well as to applications and Docker-based services. Applications are treated the same way, whether they run as a container, in a VM or on another host.

| Category | Client / application | Initial permission idea |
|---|---|---|
| Device | Tasmota devices | Own topics; Tasmota-specific profile |
| Device | Other MQTT devices (e.g. meter reading) | Defined measurement and, if needed, control topics |
| Application | TasmoFleet | Topics required for device management |
| Application | Smart home hub (e.g. Home Assistant) | Released status and telemetry topics, individual commands |
| Application | Control and automation services | Read required sensor values, publish defined commands |
| Application | Data services (e.g. energy or weather forecasts) | Read required data or publish own data |
| Application | Gateways to other systems (e.g. KNX) | Explicitly configured topics |
| Application / Docker | MQTT Viewer | Read access to released topics |
| Service | PMSS | Only `$CONTROL/dynamic-security/#`, no access to payload topics |

The table lists typical categories. The concrete clients and permissions are derived from the topic inventory (section 6.3).

### 2.1 Identity per client

A client object contains at least:

- unique internal identifier,
- display name,
- client category (Device or Application),
- manufacturer or application, if known,
- MQTT user name,
- assigned permission profile,
- optional individual topic exceptions,
- activation status,
- TLS capable: yes / no / unknown,
- TLS required: yes / no – "yes" means login with a certificate of the app CA without a password (section 7.1),
- HTTP access available: yes / no (fallback path, see 6.2),
- notes.

Client ID and user name are not the same. Dynamic Security distinguishes the user name and, optionally, a fixed client ID.

**User names** (PMSS 5.4, 6.4):

- Password clients: without `=` and `,`, e.g. the Tasmota topic.
- Certificate clients: subject of the app certificate, e.g. `CN=homeassistant,O=mqtt-apps`, without a password.
- `pmss-*` is reserved for the admin identities and their successors (`pmss-admin-2` etc.).
- Tasmota topics must not start with `pmss-` and must not contain `=` or `,`; TasmoFleet blocks devices with an invalid topic.

**Managed objects** (D-14, question 24): Roles and groups managed by PMSS carry the prefix `tf_` (e.g. `tf_role_tasmota`). Clients keep their name and are marked with `managed-by: pmss` in `textdescription`. PMSS only changes managed objects; anything created with `mosquitto_ctrl` stays protected.

## 3. Functional permission model

The model distinguishes:

1. **Clients / identities** – individual devices and applications.
2. **Permission profiles** – reusable functional rules, mapped to roles in DynSec.
3. **Topic permissions** – concrete publish and subscribe permissions.
4. **Individual exceptions** – additional or restricted permissions of a single client.

### 3.1 Treat publish and subscribe separately

The model distinguishes:

- publishing messages (`publishClientSend`),
- subscribing to topic filters (`subscribePattern` / `subscribeLiteral`),
- receiving messages (`publishClientReceive`).

A successful SUBSCRIBE does not mean that messages may be delivered. Both must be secured. Confirmed in the test: Home Assistant gets a SUBACK "Granted" for `stat/#`, yet the FILEDOWNLOAD message is not delivered.

`publishClientReceive` and `unsubscribe` are allowed by default in DynSec. Deny-by-default (D-16) is set during the initial setup with `setDefaultACLAccess`: `publishClientSend`, `publishClientReceive` and `subscribe` deny, `unsubscribe` allow (PMSS 6.2). This is not part of REST API v1, but stays with `mosquitto_ctrl`. ✅ Tested.

### 3.2 Example permission profiles

| Profile | Read / subscribe | Write / publish |
|---|---|---|
| Tasmota device | Own command topics | Own status and telemetry topics |
| Measurement and metering devices | Required control/status topics | Own measurements |
| TasmoFleet service | Status, telemetry and response topics | Required command topics |
| Home Assistant | Released status, telemetry and discovery topics | Released command and discovery topics |
| MQTT monitor / viewer | Released topics | None |
| Control and automation service | Required sensor and status data | Defined commands |
| Data service (e.g. forecasts) | Required input data | Own forecast/status data |
| Gateway to another system | Explicitly configured topics | Explicitly configured topics |
| Legacy (transition) | Everything under `#`, no `$SYS/#`, no `$CONTROL/#` | Everything under `#` |

**Command permissions for applications:** Publish on `cmnd/+/#` means full control over the devices, including `MqttPassword`, `Reset` and `Backlog`. Applications such as Home Assistant are limited to individual commands where possible (e.g. `cmnd/<topic>/POWER`).

### 3.3 Rules based on the client ID are not a security boundary

As long as several devices share one user, permissions per device can only be separated via the client ID (`%c`). The client ID is not authenticated. Such rules protect against misconfiguration, not against a compromised client. Real separation only comes with individual credentials (section 6). Therefore permissions are only restricted once individual credentials can be distributed (section 9).

## 4. Tasmota topics and naming convention

The basis is `docs/mqtt-broker-acl.md` in the TasmoFleet repository. The rules must not be adopted unchecked as a complete model.

**Convention:** The MQTT user name of a Tasmota device equals its Tasmota `Topic`. A generic profile with `%u` is therefore sufficient. ✅ Decided (D-15); the user name therefore gets no prefix.

DynSec only replaces `%u` and `%c` from Mosquitto **2.1**. In 2.0.x, ACL topics are compared literally, so `cmnd/%u/#` never matches. With 2.1.2 the profile works (role `role_tasmota`, group `group_tasmota`). ✅ Tested.

| Direction | Topic | Note |
|---|---|---|
| Subscribe | `cmnd/%u/#` | Own commands |
| Subscribe | `cmnd/<GroupTopic1…4>/#` | Up to four per device |
| Subscribe | `cmnd/<FallbackTopic>/#` | Contains the MAC, e.g. `cmnd/<mac>_fb/#` |
| Publish | `stat/%u/#` | Responses, including FILEDOWNLOAD |
| Publish | `tele/%u/#` | Telemetry, including LWT (retained) |
| Publish | `tasmota/discovery/<MAC>/#` | Depends on the MAC, not on the topic |

GroupTopic, FallbackTopic and discovery do not fit the scheme with `%u`.

**Role per device** (D-53, specification S-7, PMSS 6.4): These topics are placed in a separate role per device named `tf_role_dev_<mac>`: MAC in lower case, 12 hex characters without separators, e.g. `tf_role_dev_a4cf12345678`. The topic is stored in the `textname` of the role. If the topic changes, a new client is created; the device role stays.

**GroupTopic1–4:** The profile must allow all GroupTopics that are actually set. From TasmoFleet 0.42.0 all four are read (hellwand/tasmofleet#1005). A device with GroupTopics that have not been read counts as incomplete for profile generation. Publish permissions on a GroupTopic must be treated like `cmnd/+/#`.

**Sensitive responses:** `stat/<topic>/FILEDOWNLOAD` contains backup content. Applications with read permission on `stat/#` are excluded from it by a deny rule. In DynSec: `publishClientReceive` deny on `stat/+/FILEDOWNLOAD` with a higher priority than the allow rule. ✅ Tested with 2.1.2:

```
addRoleACL role_homeassistant publishClientReceive stat/# allow
addRoleACL role_homeassistant publishClientReceive stat/+/FILEDOWNLOAD deny 10
```

Without a priority, both rules have priority 0 and the order is undefined.

**ACL fields in the PMSS API** (question 29, PMSS v0.11): `acltype` and `topic` are required, `allow` is **required without a default** (without `allow`, DynSec creates a deny rule), `priority` is optional (default 0). If a deny rule does not have a higher priority than an allow rule of the same type in the same role, PMSS returns a warning (`warnings` in the response).

The legacy role of the first migration still reads FILEDOWNLOAD, as before the migration. This ends when the legacy role is replaced.

## 5. Architecture

### 5.1 Three layers

| Layer | Task | Technology |
|---|---|---|
| 1. External administration | TasmoFleet and administrators change clients, profiles and credentials | REST API according to interface specification v1 (`/api/v1/…`), implemented by PMSS, via HTTPS (NPM), only tokens of the OIDC provider (Keycloak or authentik) |
| 2. Internal management | PMSS applies changes to the broker | MQTT 5 over TLS in the private Docker network, port 8884, admin certificate only, `$CONTROL/dynamic-security/v1` |
| 3. MQTT access | Devices and applications connect and use topics | Authentication and topic permissions by Dynamic Security, listeners 1883, 8883, 8885 |

```
Administrator ──┐
                ├─ HTTPS + OIDC token ─────► NPM ─► PMSS ─ MQTT/mTLS :8884, admin certificate (private network) ─► Mosquitto + DynSec
TasmoFleet ─────┘                                                                                                   ▲
                                                       MQTT :1883 (IoT network, password) ──────────────────────────┤
                                                       MQTTS :8883 (TLS, password) ─────────────────────────────────┤
                                                       MQTTS :8885 (app certificate only) ──────────────────────────┘
                                                                     Devices and applications
```

### 5.2 Roles of the components

**PMSS**

- is the only DynSec admin on the broker (identity `pmss-admin`),
- is the reference implementation of interface specification v1 (D-52),
- stores no state; provides the actual state of the managed objects via `GET /api/v1/export`,
- logs in only with a certificate of the admin CA, without a password,
- manages only roles and groups with the prefix `tf_` and clients with the marker `managed-by: pmss`; other objects stay unchanged (PMSS SEC-27),
- enforces the naming rules: `pmss-*` and `role_security_manager` reserved, no password for `CN=` clients, no `=`/`,` in names of password clients,
- checks every token against the OIDC provider (signature via JWKS, issuer, audience, expiry time, `scope` claim, scopes `read`/`write`),
- logs every change with the user from the token.

Details on the API are in the interface specification, details on deployment and implementation in the PMSS detail document.

**Admin role `role_security_manager`:** `mosquitto_ctrl dynsec init` creates the role `admin` with read access to `#`. During the initial setup it is replaced by `role_security_manager` and deleted. `role_security_manager` may only access `$CONTROL/dynamic-security/#` and `$SYS/#`. ✅ Confirmed in the test: the admin can manage DynSec, but can neither read `tele/#` or FILEDOWNLOAD nor publish on `cmnd/…`.

**Admin identities:** `pmss-admin` (PMSS) and `pmss-breakglass-admin` (emergency, offline). An admin certificate is blocked with `deleteClient`, not with `disableClient`. A successor gets a sequential number (`pmss-admin-2`), because under the old name the old certificate would get admin permissions again.

**TasmoFleet**

- provides the user interface for clients, profiles, exceptions and the switch-over of devices,
- knows the Tasmota topics (GroupTopics, FallbackTopic, MAC) and derives profiles and device roles `tf_role_dev_<mac>` from them,
- holds the target state, calculates the diff against the PMSS export, obtains the approval of `security-admin` and shows the drift report (section 7.3),
- writes new credentials to the devices via `Backlog` (section 6.2),
- distributes the new fingerprint to Tasmota devices with TLS when the server certificate is renewed,
- later issues app certificates (intermediate CA with CRL or a separate TasmoFleet CA, question 30),
- talks to the broker only as a normal MQTT client, never as DynSec admin,
- calls the REST API according to interface specification v1 for changes to permissions and credentials, with a token of the logged-in user obtained via token exchange; this requires the OIDC login (section 7.2).

**Broker**

- Mosquitto 2.1 or later (tested with 2.1.2, integration tests and production with 2.1.4) with Dynamic Security, e.g. in [IOTstack](https://github.com/SensorsIot/IOTstack) (Docker Compose),
- initialising and activating the plugin remain the task of the broker administrator; the initial setup runs offline in a container without network (PMSS 6.2).

### 5.3 Initial state and target

| State | Management | Classification |
|---|---|---|
| Initial state | `password_file`, possibly `acl_file` | To be replaced |
| Phase 0 | DynSec with `mosquitto_ctrl` | Manual, small first migration |
| Target | DynSec via PMSS, user interface in TasmoFleet | No direct broker access by TasmoFleet |

Classic ACL is no longer a target backend. An ACL export from TasmoFleet is deferred (D-17).

Without an active ACL file, authenticated clients have access to all topics. With a shared user, even an ACL file helps only to a limited extent (section 3.3).

### 5.4 Note on the upstream project

TasmoFleet is an upstream project (hellwand/tasmofleet), PMSS is a separate project. So that TasmoFleet upstream does not depend on PMSS, the integration is based on the **interface specification "MQTT Security Service API v1"** (`mqtt-security-service-api-v1`, D-52, question 16). It defines paths, fields, status codes, error codes, `ETag` rules and examples as binding, as well as the requirements for the OIDC provider and the rules for the token exchange. PMSS is the reference implementation; any other implementation of the specification can replace PMSS. In case of deviations, the specification applies.

## 6. Individual MQTT credentials and migration

Individual credentials per device and application are the actual security measure. Without them, the separation remains a rule based on the client ID (section 3.3).

### 6.1 Migration principles

1. Record existing clients, credentials and topic usage.
2. Prepare target identities and profiles.
3. Provide new permissions on the broker.
4. Switch over one client or a small group.
5. Check the connection and allowed/disallowed communication.
6. Only then withdraw old permissions or shared credentials.

The migration does not require all devices to be switched over at the same time. A fallback path is provided.

**First migration (phase 0):** The existing shared user `legacy-shared-user` is taken over into DynSec with its **current password** (decision on question 26, D-30):

- DynSec stores passwords in the same `$7$` format as `pwfile`. The hash is taken over with `import-pwfile.py`. Prerequisite: the `pwfile` contains `$7$` hashes (check beforehand). ✅ Takeover tested.
- No device and no application is touched; there is no migration window for passwords.
- Permissions via the legacy role `role_legacy`: everything under `#`, but no `$SYS/#` and no `$CONTROL/#`. Applications that subscribe to `$SYS` lose this access.
- `legacy-shared-user` and `role_legacy` are not managed for PMSS (no marker, no prefix). Changes only via break-glass; they are deleted during the cleanup.
- **Fallback:** `pwfile` stays in place unchanged. Going back means restoring the saved `mosquitto.conf` and restarting. Cleanup happens after phase 4 (section 9).

After that, individual clients are switched over to their own users and the permissions are restricted.

### 6.2 Distributing credentials to devices

1. TasmoFleet requests a new client from PMSS.
2. PMSS creates the client in DynSec, generates the password and returns it once to TasmoFleet (question 25).
3. TasmoFleet transfers it to the device via `Backlog MqttUser <user>; MqttPassword <passwort>`.
4. The device reconnects.
5. TasmoFleet checks the connection and the allowed communication.

**Passwords** (D-41, D-42): The caller can supply a password; if it is missing, PMSS generates one. Every password consists of exactly 24 characters `A–Z a–z 0–9`. Reason: in `Backlog`, `;` separates the commands and a space separates command and value. Tasmota requires at least 5 characters and sets no maximum length.

**Password change:** A password change does not change the `ETag` of the client (specification S-5). Two simultaneous changes for the same client would therefore both succeed; TasmoFleet allows only one running password change per client (specification 4.4).

**Permission:** Only `security-admin` may write new credentials to devices (D-25).

**Fallback path:** With wrong credentials, the device can no longer be reached via MQTT. The way back is the HTTP API of the device. Devices with `SetOption128 1` (HTTP API disabled) have no way back; TasmoFleet checks this beforehand and blocks or warns.

**Decided (D-54, question 15):** TasmoFleet does not store passwords permanently, but only until the successful transfer to the device or until the switch-over is aborted. PMSS returns a generated password only once.

**Still to be clarified:**

- rotation of passwords,
- provisioning of devices and applications without Tasmota.

### 6.3 Recording the topic inventory

Subscribing to `#` does not show which client published. The mapping is only possible via the broker: Mosquitto with debug logging ("Received PUBLISH from <clientid>").

**Defined (question 28):**

- Observation for **one week** after the functional test of the first migration, without blocking; afterwards debug logging is switched off. Switching on and off via SIGHUP, without restart. ✅ Tested.
- **Log destination:** a central syslog service, e.g. [phylax-syslog-service](https://github.com/Noschvie/phylax-syslog-service), via the Docker logging driver `syslog` (PMSS 6.6).
- **Observing and restricting are separate:** The observation runs in parallel with the TLS listeners and the PMSS introduction; restricting only happens afterwards (section 9).
- The logs contain client IDs, user names, IP addresses and topics, no payload.

Tool: `mqtt-acl-verify inventory <log> -p -u -x` evaluates the log files of the syslog service, including denied publishes. The parser accepts syslog header lines and the tab as `#011`.

## 7. Security and operational boundaries

- TasmoFleet gets no DynSec admin permissions.
- Administrative credentials (admin certificates) are held only by PMSS or offline (break-glass).
- The DynSec admin has no access to payload topics (`role_security_manager`, section 5.2).
- Credentials do not appear in logs, diagnostic output, error responses or unprotected exports.
- Changes to permissions are logged in PMSS with user, time, and before and after state.
- Unknown or unmanaged clients are not enabled across the board.
- Before changes, the actual state is backed up: TasmoFleet stores the export, the host backs up `dynamic-security.json` regularly.
- An error in TasmoFleet must not overwrite all broker permissions; PMSS only changes managed objects (prefix `tf_` or marker).
- Old retained messages (e.g. discovery) remain when permissions change. How to handle them is still to be defined.

### 7.1 Transport security

TLS cannot be required for all clients. Decided (questions 19, 20; PMSS v0.8):

| Listener | Network (firewall on the router) | Purpose | Login |
|---|---|---|---|
| 1883, plain text | IoT network | Devices and applications without TLS | Password |
| 8883, TLS | LAN, IoT network if needed | Clients with TLS, e.g. Tasmota with TLS | Password |
| 8885, TLS | LAN | Applications with "TLS required" | Only certificate of the app CA, user name = subject |
| 8884, TLS (internal) | Private Docker network, not published | DynSec admins only | Only certificate of the admin CA, user name = CN |

The network restriction is done by a firewall rule on the router and is not part of this project. The minimum TLS version is 1.2 (Tasmota).

**Certificates:**

| CA | Purpose |
|---|---|
| Server CA | Server certificates: internal (SAN `mosquitto`, port 8884) and external (SAN `mqtt.example.org`, RSA, 12 months, ports 8883 and 8885) |
| Admin CA | Only certificates for `pmss-admin` and `pmss-breakglass-admin` |
| App CA | Only certificates for applications, subject `/O=mqtt-apps/CN=<name>`; later TasmoFleet issues them (form open, question 30). A compromised certificate is blocked with `deleteClient`; the successor gets a new subject (e.g. `CN=homeassistant-2`), otherwise the old certificate would be valid again |

All CA keys are kept offline. Every listener with client certificates trusts exactly one client CA.

**Admin only via TLS, enforced on the broker (D-20, questions 17, 18, 27):** The admins have no password and log in only with a certificate of the admin CA on 8884 (`use_identity_as_username`). A client without a password cannot log in on any password listener. Listener 8884 is set up before DynSec is activated, the initial setup runs offline, and the bootstrap admin from `dynsec init` is deleted afterwards. At no time can an admin log in via 1883.

**"TLS required" (D-21, question 20):** DynSec cannot bind a client to a listener; a password is valid on 1883 and 8883 alike. TLS can only be enforced via certificate clients: a client with "TLS required" has no password and logs in with an app certificate on 8885. ✅ Tested: its name is rejected on 1883 and 8883.

**No collision between app and admin certificates:** On the app listener, the user name is the full subject (`use_subject_as_username`). An app certificate with `CN=pmss-admin` becomes `CN=pmss-admin,O=mqtt-apps` and has no admin permissions. ✅ Tested.

**Annual renewal of the server certificate:** Tasmota checks its own CA via fingerprint. The new fingerprint is entered in `MqttFingerprint2` beforehand, then the certificate is replaced (PMSS 5.4).

**Residual risk:** Without TLS, someone in the device network can read credentials. The risk remains until the affected clients support TLS; it is limited by the network separation.

### 7.2 OIDC provider (Keycloak, authentik)

**Principle:** The PMSS REST API accepts only tokens of the configured OIDC provider that users use to log in to TasmoFleet (D-55, replaces D-28). Keycloak and authentik are tested. PMSS checks signature (JWKS), issuer, audience, expiry time, the `scope` claim and the scopes `read`/`write`, no roles or groups (question 21, specification 2.1).

**People – role `security-admin`** (D-22, decided)

- Separate role or group in the provider, not an additional permission of `admin`.
- Second factor (OTP or WebAuthn) via a conditional login flow in the provider, only for `security-admin`, for all login paths that lead to a token with scope `write` (browser, Device Authorization Grant, token exchange afterwards). PMSS does not check `acr`/`amr` (question 22).
- The provider issues `write` only to `security-admin`. This enforces D-22 in the provider, and PMSS stays independent of TasmoFleet roles.
  - **Keycloak:** role mapping on the client scope `write`. Without `security-admin`, the token exchange responds with `200` and `scope=read`. ✅ Confirmed with Keycloak 26.8.2, also for service accounts (PMSS 7.9, `test/integration/keycloak`).
  - **authentik:** expression policy on the PMSS application. Without `security-admin`, authentik rejects the whole request with `write` (`400 invalid_grant`). ✅ Confirmed with authentik 2026.8.6 (PMSS 7.9, `test/integration/authentik`).

| Function | operator | admin | security-admin |
|---|---|---|---|
| View devices, send commands | ✅ | ✅ | ❌ |
| Configure devices, backup/restore | ❌ | ✅ | ❌ |
| Manage MQTT clients, profiles and exceptions | ❌ | ❌ | ✅ |
| Review (diff) and apply changes to the broker | ❌ | ❌ | ✅ |
| Create, change, disable MQTT credentials | ❌ | ❌ | ✅ |
| Write new MQTT credentials to devices | ❌ | ❌ | ✅ |
| View the audit log of approvals in TasmoFleet | ❌ | read-only | ✅ |

Roles without security permission do not see MQTT credentials, not even masked.

**Audit:** TasmoFleet keeps its own audit of approvals (who approved which diff); `admin` may read it. The PMSS audit (before and after state) goes into the log to the central syslog service, access only for operations. PMSS has no audit endpoint.

**Tokens** (questions 14, 22; D-31):

| Caller | Flow | Scopes |
|---|---|---|
| TasmoFleet on behalf of a user | Token exchange (RFC 8693) at the same provider: exchange the user token for a token with `aud` = PMSS; `sub` remains the user | `read`, `write` only for `security-admin` |
| Administrator via `curl` | Device Authorization Grant, login in the browser with second factor | `read`, `write` only for `security-admin` |
| Scripts, monitoring, drift check | Client credentials (service account) | `read` only |
| Automated tests | Client credentials in the test environment | `read`, `write` |

In production, no service account has the scope `write`, because a service account has no second factor. TasmoFleet is a confidential client with token exchange enabled. `GET /api/v1/export` and `GET /api/v1/info` only need `read`.

**Rules for TasmoFleet** (specification S-16, S-17):

- The Security Manager requires the OIDC login (`TASMOFLEET_AUTH_MODE=oidc`). In header mode and with local accounts there is no user token to exchange.
- TasmoFleet exchanges a valid access token of the session and refreshes it beforehand if needed.
- TasmoFleet requests `write` only for `security-admin`, falls back once to `read` if rejected, and in any case evaluates `scope` of the exchanged token.
- TasmoFleet obtains tokens via the same public URL as the login. authentik builds the issuer from the host name of the request; PMSS rejects a token obtained via a different name.

**Differences between the providers** (PMSS 7.5, T-8, T-9):

| Topic | Keycloak | authentik |
|---|---|---|
| Fixed issuer | `KC_HOSTNAME` | All callers via the same public URL |
| `write` without `security-admin` | `200`, `scope=read` | `400 invalid_grant` |
| Detecting access tokens | Claim `typ` = `Bearer` | `scope` claim and audience; no `typ` claim |
| `azp` in the exchanged token | TasmoFleet | PMSS |
| Token exchange | Standard token exchange on the TasmoFleet client | Grant "Token exchange", PMSS provider trusts the TasmoFleet provider |
| Configuration as code | Realm JSON | Blueprint |
| Minimum version | 26.2 | 2026.8.3 |

**Dependency on the provider:** If the provider cannot be reached, no new tokens can be issued and therefore no permissions can be changed. PMSS continues to check already issued, valid tokens with the cached JWKS keys. Devices are not affected. For emergencies, `mosquitto_ctrl` with the certificate `pmss-breakglass-admin` remains available (break-glass, monitored; D-24).

Since PMSS checks every token on every request, the problem from v0.2 that MQTT checks a token only at CONNECT no longer applies.

### 7.3 Target state, diff and drift

Decided (question 23, PMSS v0.11). PMSS stores no state; everything that needs state lives in TasmoFleet or on the host. Paths according to interface specification v1.

| Task | Where | Implementation |
|---|---|---|
| Target state (clients, profiles, exceptions) | TasmoFleet | Functional model |
| Actual state | PMSS | `GET /api/v1/export`: all managed objects as one JSON, with `etag` per object, sorted by Unicode code points |
| Diff and approval | TasmoFleet | Target against export; applied only after approval by `security-admin` |
| Backup before applying | TasmoFleet | Store the export |
| Backup independent of TasmoFleet | Host | Back up `dynamic-security.json` regularly; also the basis for break-glass |
| Drift report | TasmoFleet | Target against export, without applying; also shows changes made via break-glass |
| Protection of unmanaged objects | PMSS | Prefix `tf_` and marker `managed-by: pmss` (D-39) |
| Concurrent changes | PMSS | `ETag` in `GET`, `If-Match` required for changes, otherwise `412` or `428`; every relationship belongs to exactly one object (group membership belongs to the group) |
| Traceability | PMSS | Audit with before and after state, without passwords |
| Change the ACL list of a role | PMSS | `PUT /api/v1/roles/{role}/acls` via `modifyRole` in one step, then read back and compare |
| Create a role with ACLs | PMSS | `POST /api/v1/roles` with `acls`, read back, delete again on deviation |
| Partial success with several commands | PMSS | Compensation path: delete the created client or role again, report the error |
| Errors | PMSS | `application/problem+json` (RFC 9457) with `status` and a fixed `code` |

This protects against errors in TasmoFleet: the limited scope (managed objects only), the validation in PMSS, `If-Match`, the audit with before state and the host backup.

## 8. Validation and tests

The test suite `mqtt-acl-verify` is run against the broker before and after each phase. The test basis is Mosquitto 2.1.2 with DynSec (`testbroker-dynsec/`), currently 59 cases plus CI steps for the control API and `$SYS`. The test cases for the interface specification and for the identity providers are in the PMSS document (section 7.9); Keycloak and authentik have separate test environments.

Column "Tested": ✅ = tested, result as expected (broker cases with `mqtt-acl-verify` against test broker 2.1.2, token cases with `check_tokens.py` of the respective provider); ⚠️ = tested, result deviates or known weakness; empty = not tested yet.

| Test case | Expectation | Tested |
|---|---|---|
| TasmoFleet reads device status/response topics | Allowed | ✅ |
| TasmoFleet publishes required device commands | Allowed | ✅ |
| Tasmota device receives its own commands | Allowed | ✅ (`%u`, from 2.1) |
| Tasmota device receives commands of other devices | Denied | ✅ |
| Tasmota device receives commands on each of its GroupTopics (1–4) | Allowed | |
| Tasmota device receives commands on a foreign GroupTopic | Denied | |
| Tasmota device publishes its own status/telemetry data | Allowed | ✅ |
| Tasmota device publishes to topics of other devices | Denied | ✅ |
| MQTT Viewer subscribes to released topics | Allowed | ✅ |
| MQTT Viewer publishes messages | Denied | ✅ |
| Application accesses topics that are not released | Denied | |
| Unknown or disabled client connects (password) | Denied | ✅ (unknown) |
| Home Assistant receives `stat/+/FILEDOWNLOAD` | Denied | ✅ |
| Existing shared user after phase 0 with current password | Allowed, permissions as before | ✅ (hash taken over) |
| Existing shared user accesses `$SYS/#` or `$CONTROL/#` | Denied | ✅ |
| DynSec admin reads payload topics or FILEDOWNLOAD | Denied | ✅ |
| DynSec admin publishes on payload topics | Denied | ✅ |
| DynSec admin connects on 1883 or 8883 | Denied | ✅ |
| DynSec admin connects on 8884 with admin certificate | Allowed | ✅ |
| Certificate of the server CA or app CA on 8884 | Denied | ✅ |
| Deleted bootstrap admin logs in | Denied | ✅ |
| Admin blocked with `deleteClient` | No permissions, open connection closed | ✅ |
| Admin blocked with `disableClient` | Denied | ⚠️ certificate login still possible, with permissions – do not use |
| Client without a valid certificate on 8884 or 8885 | Denied | ✅ |
| Certificate of the admin CA with unknown CN | No permissions | ✅ connects, without permissions |
| Password client via TLS on 8883 | Allowed, permissions as on 1883 | ✅ |
| Application with app certificate on 8885 | Allowed, permissions of its role | ✅ |
| App certificate with `CN=pmss-admin` | No admin permissions | ✅ |
| Client with "TLS required" (app certificate) on 1883 or 8883 | Denied | ✅ |
| TLS version below 1.2 on 8883/8885 | Denied | ✅ |
| App certificate via intermediate CA on 8885 | Allowed if the chain is sent along | ✅ (manual) |
| Intermediate CA revoked via CRL of the app CA | Certificates of the intermediate CA rejected | ⚠️ has no effect – Mosquitto checks the CRL only for the client certificate (manual) |
| Client certificate revoked via CRL, then SIGHUP | Rejected | ✅ (manual) |
| TasmoFleet publishes on `$CONTROL/dynamic-security/#` | Denied | |
| PMSS API without token | 401 | |
| PMSS API with a token of a foreign issuer or an expired token | 401 | |
| PMSS API with a token without `scope` claim | 401 | |
| PMSS API with a token without scope `write` for changes | 403 | |
| Token exchange for a user without `security-admin` (Keycloak) | Exchanged token without `write`, change → 403 | ✅ token without `write` (Keycloak 26.8.2) |
| Token exchange for a user without `security-admin` (authentik) | Request with `write` rejected, with `read` successful | ✅ (authentik 2026.8.6) |
| Token exchange for `security-admin` (Keycloak, authentik) | `aud` = PMSS, `sub` = user, change allowed | ✅ token as expected (both) |
| Original TasmoFleet token without `aud` = PMSS | 401 | ✅ token without `aud` = PMSS (both) |
| Token exchange of a token not issued for TasmoFleet | Rejected | ✅ (both) |
| Second factor: no path to a token with `write` without second factor | Rejected | (manual, per provider; authentik deferred) |
| PMSS changes an unmanaged object (e.g. `legacy-shared-user`, `role_legacy`) | 403 | |
| DynSec: `addRoleACL` without `allow` | Deny rule | ✅ (manual) – hence `allow` required in the API |
| DynSec: `modifyRole` with an invalid ACL entry | Error | ⚠️ entry is silently dropped (manual) – PMSS validates itself |
| PMSS API: ACL without `allow` or with unknown `acltype` | 422 | |
| PMSS API: change with outdated `If-Match` | 412, nothing changed | |
| PMSS API: `POST /api/v1/clients` with a non-existent role | Client deleted again, error reported | |
| PMSS creates a client without a password | Response contains 24 characters `A–Z a–z 0–9`, login possible | |
| Supplied password with `;`, space or a different length | 422 | |
| PMSS creates client `pmss-…` or sets a password for a `CN=` client | Denied | |
| User without `security-admin` sees MQTT credentials | Denied | |

Also to be tested:

- FILEDOWNLOAD and FILEUPLOAD,
- discovery and discovery configuration,
- GroupTopic1–4 and FallbackTopic,
- retained messages,
- wildcard subscriptions,
- priority of roles and ACL rules in DynSec (✅ tested for FILEDOWNLOAD),
- default values of `setDefaultACLAccess` (✅ tested),
- behaviour of existing connections after permission changes,
- reconnect after broker restart,
- fallback path via HTTP after a failed switch-over,
- evaluation of a real log from the syslog service with `mqtt-acl-verify inventory`.

A successful CONNECT or SUBSCRIBE alone is no proof of security. What is tested is what can actually be received and published.

## 9. Implementation phases

The phases correspond to the PMSS detail document. Permissions are only restricted once individual credentials can be distributed (question 28).

| Overview | PMSS | Content |
|---|---|---|
| Phase 0 | Phases 0–4 | First migration to DynSec |
| Phase 1 | Observation, phase 5 | Topic inventory, TLS listeners 8883 and 8885 |
| Phase 2 | Phase 6 | PMSS |
| Phase 3 | – | TasmoFleet integration |
| Phase 4 | Phase 7 | Individual credentials, restrict permissions, clean up |

### Phase 0 – First migration to DynSec (PMSS 0–4)

- [ ] Back up configuration, password file and data directory.
- [ ] Check the hash format of the `pwfile`: `$7$`.
- [ ] Identify applications that subscribe to `$SYS/#`.
- [ ] Create server CA and admin CA, set up listener 8884 with `use_identity_as_username` – before activating DynSec.
- [ ] Initial setup offline: `dynsec init`, default deny, `role_security_manager`, `pmss-admin` and `pmss-breakglass-admin` without password, `role_legacy`, `legacy-shared-user`; delete role `admin` and the bootstrap admin.
- [ ] Take over the password hash of `legacy-shared-user` with `import-pwfile.py`.
- [ ] Switch off `password_file` in the configuration (the file stays in place), logging driver `syslog`, restart.
- [ ] Run `mqtt-acl-verify` before and after; functional test without changes to devices.

Template for the DynSec commands: PMSS 6.2 and `testbroker-dynsec/dynsec-setup.txt` in `mqtt-acl-verify`.

### Phase 1 – Observation and TLS listeners

- [ ] Topic inventory: one week of `log_type all`, then switch off; evaluation with `mqtt-acl-verify inventory`.
- [ ] App CA and external server certificate `mqtt.example.org` (RSA, 12 months).
- [ ] Set up listeners 8883 (TLS with password) and 8885 (app certificate); firewall rules on the router.
- [ ] Define the client and permission model; design profiles from the inventory as DynSec roles (do not apply yet).
- [ ] Verify the Tasmota ACL documentation.

### Phase 2 – PMSS

- [ ] Go service with REST API according to interface specification v1, token check for the OIDC provider (`scope` claim required, `typ` check per provider), naming rules and audit log.
- [ ] Check for managed objects (prefix `tf_`, marker), password generation.
- [ ] `GET /api/v1/info`, `GET /api/v1/export`, `POST /api/v1/roles` with ACLs, `PUT /api/v1/roles/{role}/acls`, `ETag`/`If-Match`, errors according to RFC 9457, audit with before and after state, compensation path.

### Phase 3 – TasmoFleet integration

- [ ] Implement interface specification v1 in TasmoFleet (question 16, D-52), including the rules for the token exchange (S-16, S-17).
- [ ] In the OIDC provider (configuration as code): role or group `security-admin`, `write` only for `security-admin`, TasmoFleet client with token exchange, login flow with second factor. Keycloak: client scope `write` with role mapping, standard token exchange. authentik: separate provider for PMSS with federation to the TasmoFleet provider and a policy for `write`.
- [ ] Profile generation from Tasmota data (GroupTopic1–4, FallbackTopic, MAC), device roles `tf_role_dev_<mac>` (D-53).

### Phase 4 – Individual credentials and restricting permissions

- [ ] Individual Tasmota credentials with fallback path via HTTP.
- [ ] Migrate further devices and applications step by step; apply profiles.
- [ ] Replace the shared user and `role_legacy`.
- [ ] Clean up: remove `pwfile`, mount and old configuration lines, delete old backups and log files of the observation (PMSS 9, note after phase 7).

## 10. Open questions

1. **Backend selection:** ~~Manual or detected?~~ ✅ No longer applies: the only target is Mosquitto with DynSec via PMSS.
2. **Classic ACL – integration:** Deferred (D-17).
3. **Dynamic Security – responsibility:** ✅ PMSS manages only roles and groups with the prefix `tf_` and marked clients (D-14, PMSS v0.10).
4. **Client management:** All MQTT clients or only explicitly registered ones?
5. **Identities:** ✅ User name = Tasmota topic (D-15).
6. **Profiles and exceptions:** Which rules belong in profiles, when are exceptions permitted?
7. **Migration:** Automated or with manual confirmation per client?
8. ~~**EMQX 5**~~ – No longer applies (D-26).
9. **Topic inventory:** ✅ Via broker logs, one week, central syslog service (section 6.3).
10. **Operational boundaries:** ✅ Target state, diff, approval and drift in TasmoFleet; actual state, protection and audit in PMSS; backup on the host (section 7.3).
11. ~~**TLS requirement with Dynamic Security**~~ ✅ Tested (20.11.2026), implemented in PMSS v0.7.
12. ~~**Roles in TasmoFleet**~~ ✅ Answered: `security-admin` (D-22).
13. ~~**Target broker**~~ ✅ Answered: Mosquitto with Dynamic Security, currently no EMQX (D-26).
14. ~~**Token from TasmoFleet to PMSS**~~ ✅ **Decided (PMSS v0.12):** user token via token exchange (RFC 8693).
15. ~~**Passwords in TasmoFleet:** Permanently or only until the transfer?~~ ✅ **Decided (D-54):** only until the successful transfer to the device or until the abort; PMSS returns a generated password only once (question 25).
16. ~~**Upstream interface:** What does the interface in TasmoFleet look like so that it is not PMSS-specific?~~ ✅ **Decided (PMSS v0.13):** TasmoFleet depends on the interface specification "MQTT Security Service API v1"; PMSS is the reference implementation (D-52, section 5.4).

### Conflicts with the PMSS document (since v0.4)

17. ~~**Admin login on port 8884**~~ ✅ **Decided (PMSS v0.7):** only a certificate of the dedicated admin CA, no password, identities `pmss-admin` and `pmss-breakglass-admin`, role `role_security_manager`.
18. ~~**Can the admin also log in on port 1883?**~~ ✅ **Decided (PMSS v0.7):** No. The admin has no password; the bootstrap admin from `dynsec init` is deleted.
19. ~~**How many listeners, and is 1883 restricted to the IoT network?**~~ ✅ **Decided (PMSS v0.8):** 1883, 8883, 8885, 8884; restriction via firewall on the router (section 7.1).
20. ~~**Can "TLS required" be enforced per client?**~~ ✅ **Decided (PMSS v0.8):** Yes, as a certificate client without password on 8885.
21. ~~**Role `security-admin` or scopes `read`/`write`?**~~ ✅ **Decided (PMSS v0.12):** PMSS checks only scopes; the OIDC provider issues `write` only to `security-admin`. "Audit log read-only for `admin`" refers to TasmoFleet's own audit of approvals; PMSS has no audit endpoint.
22. ~~**Where does the token come from, and who checks the second factor?**~~ ✅ **Decided (PMSS v0.12):** TasmoFleet via token exchange; administrators via Device Authorization Grant; service accounts in production `read` only. The second factor is checked only in the OIDC provider.
23. ~~**Where are diff, approval, backup, drift report and prefix check located?**~~ ✅ **Decided (PMSS v0.11):** diff, approval, drift report and backup before applying in TasmoFleet; PMSS provides the export, protects unmanaged objects, requires `If-Match` and logs before and after state; the host backs up `dynamic-security.json` (section 7.3).
24. ~~**Prefix `tf-` and naming convention do not fit together.**~~ ✅ **Decided (PMSS v0.10):** prefix `tf_` only for roles and groups; clients keep their name (Tasmota topic or `CN=…`) and are marked via `managed-by: pmss` in `textdescription`. `legacy-shared-user` and `role_legacy` stay unmanaged. Successors of blocked identities get a sequential number.
25. ~~**Who generates the password?**~~ ✅ **Decided (PMSS v0.10):** The caller can supply a password, otherwise PMSS generates one and returns it once. Format: exactly 24 characters `A–Z a–z 0–9`. `PUT …/password` becomes `POST …/password`.
26. ~~**First migration: compatible and small, or a new password for everyone?**~~ ✅ **Decided (PMSS v0.9):** compatible; the password hash is taken over, no device is touched, `pwfile` stays as fallback.
27. ~~**Admin in plain text during the transition?**~~ ✅ **Decided (PMSS v0.7):** listener 8884 before DynSec activation, initial setup offline.
28. ~~**Order: restrict permissions before or after PMSS?**~~ ✅ **Decided (PMSS v0.9):** observe after the first migration (one week), restrict only with individual credentials after PMSS.
29. ~~**Test basis and API fields**~~ ✅ **Decided:** test basis Mosquitto 2.1.2 with DynSec; ACL fields in the API: `allow` required, `priority` optional, default 0 (PMSS v0.11).
30. ⚠️ **Signing key for TasmoFleet: intermediate CA with CRL or a separate TasmoFleet CA?** To be decided before the TasmoFleet expansion stage.
    - Tested (20.11.2026): Mosquitto checks a CRL only for the client certificate. Revoking an intermediate CA has no effect; with a compromised key, the app CA would have to be replaced.
    - Separate TasmoFleet CA: in an emergency, remove it from `cafile` and restart (SIGHUP is not enough); requires two trusted CAs on 8885.
    - Intermediate CA: individual certificates can be blocked via CRL; CRLs of all issuing CAs must be maintained. `nameConstraints` still to be checked.
    - Comparison in the PMSS document, section 5.4.
31. ~~**Identity provider: only Keycloak or also authentik?**~~ ✅ **Decided (24.11.2026):** Both, because TasmoFleet supports login with Keycloak and with authentik. PMSS and the specification do not depend on a specific provider (D-55, specification S-15); the differences are covered by specification S-16/S-17 and PMSS T-8/T-9. Minimum version authentik 2026.8.3 (token exchange from 2026.8.0). Open: second factor with authentik (app passwords).

## 11. Architecture decisions

| ID | Decision | Status |
|---|---|---|
| D-01 | Common functional permission model | For review |
| D-02 | Mosquitto Classic ACL as backend | Deferred (initial state only) |
| D-03 | Mosquitto Dynamic Security as backend | ✅ Decided (see D-26) |
| D-04 | Individual credentials per Tasmota device as a medium-term goal | For review |
| D-05 | Broker remains independent of TasmoFleet operation | For review |
| D-06 | Common functional test suite (`mqtt-acl-verify`) | For review |
| D-07 | Consider EMQX 5 in the architecture | Deferred (D-26) |
| D-08 | Manage MQTT clients independent of manufacturer and origin | For review |
| D-09 | Devices and applications as client categories | For review |
| D-10 | Reusable permission profiles | For review |
| D-11 | Individual credentials for applications as well | For review |
| D-12 | Tasmota rules as a specialised profile | For review |
| D-13 | Docker applications as independent MQTT clients | For review |
| D-14 | Target state with diff, drift report, prefix for managed objects | ✅ Decided: prefix in PMSS (D-39), diff and drift in TasmoFleet (D-43) |
| D-15 | MQTT user name = Tasmota topic | ✅ Decided (PMSS v0.10) |
| D-16 | Deny-by-default for all profiles | For review (implementation in DynSec tested) |
| D-17 | Classic ACL only as export | Deferred |
| D-18 | Rules based on the client ID are not a security boundary | For review |
| D-19 | Broker with listeners with and without TLS: 1883, 8883, 8885, 8884 | ✅ Decided (PMSS v0.8) |
| D-20 | Admin access only via TLS, enforced on the broker | ✅ Decided (PMSS v0.7, SEC-17) |
| D-21 | "TLS required" per client = login with app certificate without password | ✅ Decided (PMSS v0.8) |
| D-22 | Security functions only for `security-admin`, second factor via the OIDC provider | ✅ Decided; implemented in the provider (`write` only for `security-admin`, conditional login flow) |
| D-23 | Broker admin via Keycloak token on the broker | ❌ Superseded by D-28 |
| D-24 | Emergency admin (break-glass) via `mosquitto_ctrl` with certificate `pmss-breakglass-admin`, monitored | ✅ Decided (PMSS v0.7) |
| D-25 | Only `security-admin` writes new credentials to devices | ✅ Decided |
| D-26 | Target broker Mosquitto with Dynamic Security, currently no EMQX | ✅ Decided |
| D-27 | TasmoFleet manages via the PMSS REST API, not directly on the broker (variant A) | ✅ Decided; refined by D-52 |
| D-28 | PMSS API accepts only tokens issued by Keycloak | ❌ Superseded by D-55 |
| D-29 | PMSS is the only DynSec admin, via admin certificate on the internal listener 8884 | ✅ Decided (PMSS v0.7) |
| D-30 | First migration: existing shared user with current password (hash taken over), compatible permissions, restrict afterwards | ✅ Decided (PMSS v0.9) |
| D-31 | TasmoFleet calls PMSS with the user's token, via token exchange (RFC 8693) | ✅ Decided (PMSS v0.12) |
| D-32 | Three internal CAs: server CA, admin CA, app CA; every certificate listener trusts exactly one client CA | ✅ Decided (PMSS v0.7/v0.8) |
| D-33 | Admin role `role_security_manager` replaces the role `admin` from `dynsec init`; blocking with `deleteClient` | ✅ Decided (PMSS v0.7) |
| D-34 | App listener with `use_subject_as_username`; naming rules against collisions | ✅ Decided (PMSS v0.8) |
| D-35 | External server certificate `mqtt.example.org`, server CA, RSA, 12 months, renewal via `MqttFingerprint2` | ✅ Decided (PMSS v0.8) |
| D-36 | App certificates manual for now, later via TasmoFleet | ✅ Decided (PMSS v0.8); form of the signing key open ⚠️ question 30 |
| D-37 | Legacy role: everything under `#`, no `$SYS/#`, no `$CONTROL/#` | ✅ Decided (PMSS v0.9) |
| D-38 | Observing (one week, central syslog service) and restricting separately | ✅ Decided (PMSS v0.9) |
| D-39 | PMSS manages only roles and groups with prefix `tf_` and clients with `managed-by: pmss` in `textdescription`; existing shared user and legacy role stay unmanaged | ✅ Decided (PMSS v0.10) |
| D-40 | Blocked admin and app names are not reused; successors with a sequential number | ✅ Decided (PMSS v0.10) |
| D-41 | Password optionally supplied by the caller, otherwise generated by PMSS and returned once | ✅ Decided (PMSS v0.10) |
| D-42 | MQTT passwords: exactly 24 characters `A–Z a–z 0–9` | ✅ Decided (PMSS v0.10) |
| D-43 | Target state, diff, approval, drift report and backup before applying in TasmoFleet; PMSS without state, actual state via the export (since v0.9 `GET /api/v1/export`) | ✅ Decided (PMSS v0.11) |
| D-44 | Host backs up `dynamic-security.json` regularly | ✅ Decided (PMSS v0.11) |
| D-45 | Replace the ACL list of a role as a whole via `PUT` (`modifyRole`), with own validation and read-back | ✅ Decided (PMSS v0.11) |
| D-46 | `ETag`/`If-Match` for modifying calls | ✅ Decided (PMSS v0.11) |
| D-47 | Audit with before and after state, without passwords | ✅ Decided (PMSS v0.11) |
| D-48 | PMSS checks only scopes `read`/`write`; the OIDC provider issues `write` only to `security-admin` | ✅ Decided (PMSS v0.12) |
| D-49 | Second factor only in the OIDC provider, for all login paths with `write` | ✅ Decided (PMSS v0.12) |
| D-50 | No service accounts with `write` in production; administrators via Device Authorization Grant | ✅ Decided (PMSS v0.12) |
| D-51 | No audit endpoint in PMSS; TasmoFleet keeps the audit of approvals | ✅ Decided (PMSS v0.12) |
| D-52 | Interface specification "MQTT Security Service API v1" as the basis of the integration: TasmoFleet depends on the specification, PMSS is the reference implementation; in case of deviations, the specification applies | ✅ Decided (PMSS v0.13) |
| D-53 | GroupTopic, FallbackTopic and discovery of a Tasmota device in a separate role `tf_role_dev_<mac>` (MAC lower case, 12 hex characters, topic in `textname`) | ✅ Decided (specification S-7, PMSS v0.13) |
| D-54 | TasmoFleet does not store MQTT passwords permanently, but only until the successful transfer to the device or until the abort (question 15) | ✅ Decided |
| D-55 | PMSS API accepts only tokens of the configured OIDC provider that users use to log in to TasmoFleet; Keycloak and authentik are tested (question 31) | ✅ Decided (specification S-15, PMSS SEC-15) |
| D-56 | TasmoFleet requests `write` only for `security-admin`, falls back once to `read` if rejected, and evaluates `scope` of the exchanged token | ✅ Decided (specification S-16) |
| D-57 | Security Manager only with OIDC login in TasmoFleet; tokens via the same public URL as the login | ✅ Decided (specification S-17, PMSS SEC-40) |

## 12. Requirements for TasmoFleet

These are collected and will later be submitted as a feature issue to hellwand/tasmofleet.

- [ ] New role `security-admin` from the existing OIDC role claim, separate from `admin` and `operator`.
- [ ] Permissions per function according to the role matrix (section 7.2).
- [ ] Roles without security permission do not see MQTT credentials.
- [ ] Fields "TLS capable", "TLS required" (= certificate client) and "HTTP access available" in the client object.
- [ ] Integration of an external security service according to the interface specification "MQTT Security Service API v1" (REST with OIDC token), without own broker admin permissions and without assumptions beyond PMSS.
- [ ] Offer the Security Manager only in OIDC mode (`TASMOFLEET_AUTH_MODE=oidc`); hide it in header mode and with local accounts (specification S-17).
- [ ] Before the first export, read `GET /api/v1/info` and check `apiVersion` (major version 1); take prefixes, marker, password rule and `limits.maxRequestBytes` from the response instead of hard-coding them.
- [ ] Handle errors by `status` and `code` (`application/problem+json`, RFC 9457), not by `title` or `detail`.
- [ ] Compare and change group membership via the group: it belongs to the group and only goes into its `ETag`, not into that of the client.
- [ ] Allow only one running password change per client (a password change does not change the `ETag`).
- [ ] Create GroupTopic, FallbackTopic and discovery per device in a role `tf_role_dev_<mac>` (MAC in lower case, 12 hex characters, topic in `textname`; D-53).
- [ ] Show warnings (`warnings`) from the responses during approval.
- [ ] Exchange the user token via token exchange (RFC 8693) at the same OIDC provider for a token for the security service (`aud` = security service); TasmoFleet as a confidential client. Exchange a valid session token, refresh it beforehand if needed; call the token endpoint via the same public URL as the login (specification S-17).
- [ ] Request `write` only for `security-admin`; if the provider rejects, retry once with `read` only; then evaluate `scope` of the exchanged token and offer modifying functions only with `write`. Without `security-admin`, Keycloak responds with `200` and `scope=read`, authentik rejects the request with `write` (specification S-16).
- [ ] Own audit of approvals (who approved which diff when), readable for `admin` and `security-admin`.
- [ ] Distribute the fingerprint of the server certificate to Tasmota devices with TLS (`MqttFingerprint2` before the change, then `MqttFingerprint1`).
- [ ] Later: issue app certificates (subject `/O=mqtt-apps/CN=<name>`, with an intermediate CA include the chain), key usable only by `security-admin`. Form of the key: question 30. Know blocked subjects and do not assign them again (PMSS SEC-23).
- [ ] Block devices with an invalid topic: topic starts with `pmss-` or contains `=` or `,` (user name = topic).
- [ ] Normally let PMSS generate new MQTT passwords; keep them only until the transfer via `Backlog` (D-54).
- [ ] Compare the target state against `GET /api/v1/export`; show the diff to `security-admin` for approval before applying.
- [ ] Store the export before applying (backup).
- [ ] Drift report: show deviations between target and export, including changes made via break-glass.
- [ ] For changes, send `If-Match` with the `ETag` from the export; on `412`, read again and present the diff for approval again.
- [ ] Set ACL lists of a role as a whole via `PUT /api/v1/roles/{role}/acls`; new roles with ACLs via `POST /api/v1/roles`.
- [x] Read, store and check all four GroupTopics – #1005, implemented in 0.42.0.
- [ ] Show the result of the check for shared topics in the user interface (status and list of collisions) – follow-up issue to #1005.

## 13. Summary

Mosquitto remains the broker (production with 2.1.4). Management via `password_file` and `acl_file` is replaced by Dynamic Security, first manually with `mosquitto_ctrl` and then via PMSS.

The first migration is small and compatible: the existing shared user keeps its password (the hash is taken over) and gets a legacy role without `$SYS` and `$CONTROL`. No device is touched; `pwfile` stays as fallback. After that, the topic inventory is recorded for one week. Restrictions only come with individual credentials after PMSS.

PMSS is the only service with admin permissions on the broker. It is reachable only via an HTTPS REST API that accepts exclusively tokens of the OIDC provider (Keycloak or authentik, the same as for the TasmoFleet login), and talks to the broker internally via port 8884, logged in only with a certificate of the admin CA, without a password. The broker rejects admins on all other listeners.

Devices and applications use 1883 (IoT network), 8883 (TLS with password) or 8885 (app certificate only). "TLS required" can only be enforced on the broker for certificate clients.

TasmoFleet provides the user interface, knows the Tasmota specifics and distributes new credentials and fingerprints to the devices. It changes permissions on the broker only via the REST API according to the interface specification "MQTT Security Service API v1". PMSS is its reference implementation; TasmoFleet upstream therefore does not depend on PMSS.

All 13 conflicts from v0.4 are decided (17 to 29), as are question 16 on the upstream interface, question 15 on storing passwords (D-54) and question 31 on the identity provider (D-55). Still open are the functional questions 4, 6 and 7 on client management, profiles and exceptions, and the migration procedure, which are to be clarified with the TasmoFleet maintainer, and, before the TasmoFleet expansion stage, the form of the TasmoFleet signing key (30).

PMSS checks only scopes; the OIDC provider ensures that only `security-admin` with a second factor gets the scope `write`. TasmoFleet calls PMSS with an exchanged user token, so the PMSS audit shows the real user. The specification covers the differences between Keycloak and authentik with fixed rules for TasmoFleet.

Diff, approval and drift report are in TasmoFleet; PMSS stays without state, provides the actual state, protects unmanaged objects and logs every change with before and after state.

**This document is an architecture draft for review.**

## 14. Overview of the conflicts

| Question | Topic | Overview | PMSS | Status 20.11.2026 |
|---|---|---|---|---|
| 17 | Admin login 8884 | Certificate only | Certificate + password (v0.6) | ✅ Certificate only, admin CA (PMSS v0.7) |
| 18 | Admin on 1883 | Rejected | Possible (v0.6) | ✅ Rejected, bootstrap admin deleted (PMSS v0.7) |
| 19 | Listeners | Plain text, TLS, mTLS | 1883, 8884 (v0.6) | ✅ 1883, 8883, 8885, 8884 (PMSS v0.8) |
| 20 | "TLS required" | Per client | Cannot be mapped (v0.6) | ✅ Certificate client on 8885 (PMSS v0.8) |
| 21 | API authorisation | Role `security-admin` | Scopes `read`/`write` | ✅ Scopes only; `write` only for `security-admin` via Keycloak (PMSS v0.12) |
| 22 | Token origin | User token / token exchange | Client credentials, device grant | ✅ Token exchange for TasmoFleet, device grant for admins, 2FA only in Keycloak (PMSS v0.12) |
| 23 | Diff, approval, drift, backup | In PMSS | Not in API v1 (v0.6) | ✅ In TasmoFleet; PMSS provides export, `If-Match`, audit (PMSS v0.11) |
| 24 | Prefix / names | `tf-`, user = topic | `tasmota-001`, `role_tasmota` (v0.6) | ✅ `tf_` for roles/groups, marker for clients (PMSS v0.10) |
| 25 | Password generation | PMSS generates | Caller supplies (v0.6) | ✅ Optionally caller, otherwise PMSS; 24 characters (PMSS v0.10) |
| 26 | First migration | Compatible, step by step | New password for everyone (v0.6) | ✅ Compatible, hash taken over (PMSS v0.9) |
| 27 | Admin during transition | TLS only | Via 1883 before phase 4 (v0.6) | ✅ 8884 before DynSec, initial setup offline (PMSS v0.7) |
| 28 | Order | Permissions before PMSS | Permissions after PMSS | ✅ Observe before, restrict after (PMSS v0.9) |
| 29 | Test basis / API fields | 2.0.18 Classic ACL | 2.1.2 DynSec | ✅ Test basis; `allow` required, `priority` optional (PMSS v0.11) |
| 30 | TasmoFleet signing key | – | Intermediate CA with CRL or separate CA | ⚠️ open, before the TasmoFleet expansion stage |

---

## References

- Interface specification "MQTT Security Service API v1" – `mqtt-security-service-api-v1` (current version)
- TasmoFleet – `docs/mqtt-broker-acl.md`: https://github.com/hellwand/tasmofleet/blob/main/docs/mqtt-broker-acl.md
- TasmoFleet – issue #1005 (all four GroupTopics): https://github.com/hellwand/tasmofleet/issues/1005
- Mosquitto Dynamic Security plugin: https://mosquitto.org/documentation/dynamic-security/
- Eclipse Mosquitto – documentation: https://mosquitto.org/documentation/
- Keycloak – documentation: https://www.keycloak.org/documentation
- authentik – OAuth2 provider and token exchange: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/
- RFC 8693 – OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
- RFC 9457 – Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc9457
- mqtt-acl-verify: https://github.com/Noschvie/mqtt-acl-verify (test broker `testbroker-dynsec/`, `import-pwfile.py`, documentation `docs/testbroker-dynsec.md`)
- PMSS – detail document `phylax-mqtt-security-service-design` (current version): https://github.com/Noschvie/phylax-mqtt-security-service
