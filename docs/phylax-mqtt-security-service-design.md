# Design: Phylax MQTT Security Service with Mosquitto Dynamic Security

**Status:** Draft for technical review\
**Version:** 1.1\
**Date:** November 25, 2026\
**Target environment:** Mosquitto in [IOTstack](https://github.com/SensorsIot/IOTstack) (Docker Compose)\
**Broker:** Eclipse Mosquitto 2.1 or later, tested with 2.1.2\
**Identity Provider:** OIDC provider with Token Exchange according to RFC 8693; tested with Keycloak 26.8.2 and authentik 2026.8.6, at least Keycloak 26.2 or authentik 2026.8.3\
**Implementation language:** Go\
**Project name:** Phylax MQTT Security Service\
**GitHub repository:** [`Noschvie/phylax-mqtt-security-service`](https://github.com/Noschvie/phylax-mqtt-security-service)\
**Short description:** A REST API service for managing Mosquitto Dynamic Security clients, roles and access control.\
**License:** GNU Affero General Public License v3 or later, SPDX `AGPL-3.0-or-later` (license text as in [TasmoFleet](https://github.com/hellwand/tasmofleet/blob/main/LICENSE))\
**Interface specification:** “MQTT Security Service API v1” (`mqtt-security-service-api-v1`, current version); PMSS is the reference implementation\
**Architecture overview:** `mqtt-security-overview` (current version)

> **Naming note**
> In this document, “Security Service” or “Service” is shorthand for the Phylax MQTT
> Security Service. The repository, image, binary, and Compose service are named
> `phylax-mqtt-security-service`.

> **Interface specification note**
> This document does not repeat the interface specification
> in full. It refers to it and describes only **how** PMSS
> implements it (DynSec commands, validation, audit, tests). In
> case of discrepancies, the specification takes precedence.

> **Names and environment note**
> Host, user, and domain names are placeholders:
> `legacy-shared-user` for the shared existing user,
> `mqtt.example.org` for the broker name used by the TLS listeners, “Broker host”
> for the machine on which IOTstack runs. Details for a specific
> installation are provided in a separate operations document.

> **Identity provider note**
> Keycloak and authentik are handled separately: they have their own sections
> for configuration (7.5) and their own tests (7.9). Unless otherwise
> stated, a statement applies to both.

------------------------------------------------------------------------

## 1. Goal and summary

The goal is to gradually replace the existing Mosquitto management
using `password_file` and optionally `acl_file` with the integrated
**Mosquitto Dynamic Security Plugin (DynSec)**.

User and permission management will initially be performed directly with
`mosquitto_ctrl`. The next development stage is planned to be a
standalone **Phylax MQTT Security Service** as a **Go application**.
It provides a REST API and communicates with the broker internally
over MQTT.

The architecture separates three tasks:

1.  **External administration:** HTTPS-protected REST API.
2.  **Internal management communication:** MQTT over TLS and mTLS in
    a private Docker network.
3.  **MQTT access for devices and applications:** Authentication and
    topic permissions through Dynamic Security.

The first migration is intentionally kept small: the shared
existing user is carried over. Permissions are initially kept
compatible with the previous state and then gradually restricted.

## 2. Initial situation

### 2.1 Typical installation

The starting point is Mosquitto as a Docker container in IOTstack:

| Characteristic | Initial state |
|---|---|
| Mosquitto version | 2.1 or later (tested with 2.1.2) |
| Dynamic Security library | `/usr/lib/mosquitto_dynamic_security.so`, included in the official image |
| `mosquitto_ctrl` | with DynSec module |
| Compose project | `~/IOTstack` |
| Mosquitto configuration | `volumes/mosquitto/config/mosquitto.conf` |
| Persistent data | `volumes/mosquitto/data` |
| Password file | `volumes/mosquitto/pwfile/pwfile` |
| MQTT user | one shared existing user, here `legacy-shared-user` |
| Listener | TCP 1883 |
| Anonymous connections | disabled (`allow_anonymous false`) |
| ACL file | optional, often not active |

### 2.2 Authentication and permissions before migration

Typical configuration in `mosquitto.conf`:

``` ini
listener 1883
password_file /mosquitto/pwfile/pwfile
allow_anonymous false
#acl_file /mosquitto/config/filter.acl
```

If no ACL file is enabled, there are no topic restrictions imposed by
a Mosquitto ACL file. Authenticated clients then generally have access
to all topics. With a shared user, an ACL file is also of limited help,
because permissions can only be separated per device using the
unauthenticated client ID.

**Migration note:** The password file contains password hashes, not
the original plaintext password. Mosquitto 2.1 stores
DynSec passwords in the same format (sha512-pbkdf2, `$7$…`) as
`encoded_password`. The hash can therefore be carried over; the
existing password therefore remains valid (tested on 20.11.2026 with Mosquitto
2.1.2). Before migration, check whether the `pwfile` contains `$7$` hashes.

> **Decision**
> The existing password hash is carried over to DynSec (Section
> 6.2). No device or application is touched during the first migration;
> there is no password migration window. The
> shared password will later be replaced by individual credentials for each
> device.

## 3. Target architecture

### 3.1 Components

| Component | Task |
|---|---|
| Mosquitto Broker | MQTT broker and execution of the DynSec plugin |
| Dynamic Security Plugin | Clients, groups, roles, ACLs, and password verification |
| `dynamic-security.json` | Persistent DynSec state |
| Phylax MQTT Security Service | Go service for the REST API (`net/http`) and MQTT Control API (Eclipse Paho Go) |
| Nginx Proxy Manager (NPM) | External HTTPS entry point and reverse proxy |
| OIDC provider (Keycloak or authentik) | Issues the bearer tokens (JWT) for the REST API; scopes `read`/`write`; the same provider where users sign in to TasmoFleet |
| Internal CAs | **Server CA:** Mosquitto server certificates (internal and for the TLS listeners). **Admin CA:** only client certificates of DynSec admins. **App CA:** only client certificates of applications with “TLS required.” CA certificates mounted separately and read-only; CA keys kept offline |

### 3.2 Communication paths

``` text
Externe Admin-Clients / Anwendungen
                |
                | HTTPS :443
                v
       Nginx Proxy Manager
                |
                | internes Proxy-Netz (HTTP)
                v
   Phylax MQTT Security Service
     Go / net/http REST API
     Debian-Slim-Container
                |
                | MQTT 5 over TLS + mTLS
                | (Eclipse Paho Go, crypto/tls)
                | internes Docker-Netz, Port 8884
                | Anmeldung nur per Admin-Zertifikat (CN = pmss-admin)
                v
          Mosquitto Broker
          DynSec Plugin
                |
                +---- Geräte ohne TLS ........... :1883 (Passwort)
                +---- Geräte/Anwendungen mit TLS  :8883 (TLS + Passwort)
                +---- Anwendungen „TLS erforderlich“
                                                  :8885 (nur App-Zertifikat)
```

The REST API and the MQTT Control API are two different
interfaces:

-   REST is the interface for admin UIs and other
    management applications.
-   MQTT is the internal interface through which the Security Service
    sends DynSec commands to Mosquitto.

The Security Service is not to edit the `dynamic-security.json` file
directly. Changes are made through the plugin's official MQTT Control API.

### 3.3 Security Service technology decision

> **Decision**
> The Phylax MQTT Security Service will be implemented in **Go** instead of Node.js.
> Packages from the Go standard library will be used wherever possible; the
> main external dependencies are the MQTT client and JWT verification.

| Area | Decision | Remark |
|---|---|---|
| Programming language | Go ✅ | Replaces Node.js ❌. Always use the current version, currently Go 1.27. |
| HTTP API | `net/http` (standard library) | Routing via `http.ServeMux` with method and path patterns (e.g. `GET /api/v1/clients/{username}`, access via `r.PathValue`). No additional web framework. |
| MQTT | Eclipse Paho Go, MQTT 5, `autopaho` | `github.com/eclipse/paho.golang/autopaho` handles connection establishment and reconnect. The service itself subscribes to the response topic in `OnConnectionUp` (Section 7.2). No separate reconnect layer over `paho`, no fallback to MQTT 3.1.1. |
| JSON | `encoding/json` | Typed structs for DynSec commands and responses |
| JWT verification | `github.com/coreos/go-oidc/v3` (with `go-jose/v4`) | `oidc.NewVerifier` with a fixed issuer and custom throttled `KeySet` (JWKS from `PMSS_OIDC_JWKS_URL`, otherwise `jwks_uri` from the discovery document), no `oidc.NewProvider`; signature, `iss`, `aud`, `exp`/`nbf`, algorithm. The service checks `scope`, `typ` (per provider), and scopes (Section 7.5, T-7 through T-9) |
| TLS/mTLS | `crypto/tls`, `crypto/x509` | Custom `RootCAs` pool with the server CA certificate, client certificate (Admin CA) via `tls.LoadX509KeyPair`, `ServerName` = broker service name, `MinVersion` TLS 1.2 or later |
| Logging | `log/slog` | Structured logging (JSON handler) for operational and audit logs |
| Container runtime | Debian Slim ✅ | `debian:trixie-slim` (Debian 13) instead of `scratch` ❌. Image size is not a decision criterion. |
| Internal CAs | Mounted separately, read-only | CA certificate as a separate `:ro` mount; CA private keys never in the container |

Rationale:

-   Statically compiled binary without runtime dependencies
    (Node.js runtime, `node_modules`) and with a small, easily auditable
    dependency list (`go.mod`/`go.sum`).
-   HTTP server, JSON, TLS, and structured logging are available in the
    are available in the standard library and are well maintained.
-   Concurrent request/response correlation can be implemented directly using
    goroutines, channels, and `context.Context` (timeouts, cancellation)
    directly.
-   Simple cross-compilation for `amd64` and `arm64`
    (`CGO_ENABLED=0`, `GOOS`/`GOARCH`).

## 4. Network and port concept

### 4.1 Listeners

Proposed listeners:

| Port | Purpose | Reachability | Encryption / authentication |
|---|---|---|---|
| 1883 | Devices and applications without TLS | IoT network | Unencrypted; username/password |
| 8883 | Devices and applications with TLS, password authentication | LAN; IoT network once devices use TLS there | TLS (server certificate from the Server CA); username/password |
| 8885 | Applications with “TLS required” | LAN | TLS, App CA client certificate only, username = certificate subject, no password |
| 8884 | Internal admin access (Phylax MQTT Security Service, break-glass) | Internal Docker network only | TLS, Admin CA client certificate only, username = CN, no password |

> **Decision**
> The internal listener uses port **8884**. mTLS is **mandatory**
> there: connections without a valid client certificate are
> rejected.

> **Decision**
> Listener 8884 accepts only certificates from the **Admin CA**.
> The username is taken from the CN
> (`use_identity_as_username true`); there is no password
> (Section 5.2). The listener is configured **before** DynSec is enabled
> (Section 9, Phase 1).

> **Decision**
> In addition to 1883 and 8884, there are two TLS listeners: **8883** for
> clients with passwords and **8885** for applications that authenticate only
> with an App CA certificate. Both are introduced as a separate phase after
> the functional test (Section 9, Phase 5). The minimum is
> TLS 1.2 (`tls_version tlsv1.2`), because Tasmota does not support TLS 1.3.
> Applications are treated the same regardless of whether they run as containers, in
> a VM, or on another host; there is no
> special path through the Docker network.

One listener cannot mix certificate and password authentication: with
`require_certificate false` and `use_identity_as_username true` cause
Mosquitto 2.1.2 to reject both types (tested 20.11.2026). Therefore there are
separate listeners for password (8883) and certificate (8885) authentication.

Port 8884 is an internal MQTT/TLS port. The port number itself
does not enable encryption; this is determined by the listener's TLS
configuration.

Port 8884 is **not** published on the Docker host via `ports:`.
The Security Service reaches the broker using the
Docker service name and port 8884.

**Reachability by network:** Restrictions are enforced through
firewall rules on the router. This is not part of this project; the
document only specifies what must be reachable:

| Port | IoT network | LAN | Remark |
|---|---|---|---|
| 1883 | ✅ | ❌ | Plaintext only on the IoT network |
| 8883 | ✅ (once devices use TLS) | ✅ | |
| 8885 | ❌ | ✅ | |
| 8884 | ❌ | ❌ | Not published, internal Docker network only |

### 4.2 Docker networks

The broker and the Security Service share a dedicated internal
network. The Security Service is additionally connected to the network
through which NPM reaches the REST service.

Conceptual example – adapt to the existing Compose file before implementation:

``` yaml
services:
  mosquitto:
    networks:
      - mqtt-internal
      - mqtt-existing

  phylax-mqtt-security-service:
    networks:
      - mqtt-internal
      - api-internal

networks:
  mqtt-internal:
    internal: true

  api-internal:
  mqtt-existing:
```

NPM must be able to reach the Security Service through a shared proxy
network. The specific network connection must be determined based on the
existing NPM and IOTstack Compose configuration.

If the Security Service loads the OIDC provider's keys over the
internal network (Section 7.5, `PMSS_OIDC_JWKS_URL`), it also needs
a shared network with the provider. This can be the
proxy network through which NPM reaches both services, or a dedicated
network only for key retrieval.

**Security boundary:** An internal Docker network prevents
normal reachability from outside and from unconnected
Docker networks. However, it does not protect against a compromised
Docker host or privileged host administrators. Network separation
is the second layer: the broker itself rejects the admin on
all other listeners (Section 5.2).

## 5. TLS and certificate concept

### 5.1 Internal CAs

> **Decision**
> **Two** internal CAs are used for the connection between the Security Service and Mosquitto:
> a **server CA** and an **admin CA**.

> **Decision**
> A third CA is added for applications with “TLS required”:
> the **App CA**. The server CA also issues the server certificate
> for TLS listeners 8883 and 8885. Let's Encrypt is not
> used.

| CA | Signs | Who trusts it |
|---|---|---|
| Server CA | Internal server certificate (SAN `mosquitto`, listener 8884) and external server certificate (SAN `mqtt.example.org`, listeners 8883 and 8885), each with `extendedKeyUsage=serverAuth` | Security Service (`RootCAs`), `mosquitto_ctrl` for break-glass, all clients on listeners 8883 and 8885 |
| Admin CA | Only client certificates for DynSec admins `pmss-admin` and `pmss-breakglass-admin` (`extendedKeyUsage=clientAuth`) | Mosquitto, listener 8884 (`cafile`) |
| App CA | Only client certificates for applications, subject `/O=mqtt-apps/CN=<name>` (`extendedKeyUsage=clientAuth`) | Mosquitto, listener 8885 (`cafile`) |

Each listener using client certificates trusts exactly one client CA:
8884 only the Admin CA, 8885 only the App CA.

The Admin CA is the actual security boundary: on listener 8884
the username is taken from the CN; there is no password.
Any certificate from the Admin CA whose CN exists in DynSec receives that
client's permissions. The Admin CA therefore issues certificates **only**
for admin identities, never for devices, applications, or servers.
A certificate from the Admin CA with a CN unknown to DynSec
can connect, but has no permissions (tested 20.11.2026).

The CAs are not made dependent on Let's Encrypt. All
CA keys are kept offline and separate from the runtime containers
and are not mounted into any container.

The **CA certificates** (public part) are mounted **separately and
read-only** into the containers: the server CA into the Security
Service, the Admin CA and App CA into Mosquitto. They are **not** installed
in the Debian image's system trust store (`/etc/ssl/certs`).
The Go service explicitly loads the server CA into its own
`x509.CertPool` and uses only this pool for the
connection to the broker. Thus, for port 8884, the service trusts only the
server CA, while the system CAs remain separate for any outbound
connections (e.g. JWKS retrieval from the OIDC provider).

### 5.2 Certificate verification and admin authentication

Mosquitto verifies the Security Service's client certificate against the
Admin CA. The Security Service verifies the broker's server certificate
against the server CA, including hostname/SAN.

The server certificate SAN must cover the broker name used internally in Docker,
for example the Compose service name
`mosquitto`.

Implementation in the Go service (conceptual):

``` go
caPEM, _ := os.ReadFile("/run/mqtt-server-ca/ca.crt")
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)

clientCert, _ := tls.LoadX509KeyPair(
    "/run/secrets/mqtt-client/pmss-admin.crt",
    "/run/secrets/mqtt-client/pmss-admin.key",
)

tlsCfg := &tls.Config{
    RootCAs:      pool,              // nur Server-CA
    Certificates: []tls.Certificate{clientCert},
    ServerName:   "mosquitto",       // SAN-Prüfung
    MinVersion:   tls.VersionTLS12,
}
```

`InsecureSkipVerify` is not used. Error handling is omitted from the
example for readability; in the code, any error when
loading the CA or certificate causes startup to abort.

> **Decision**
> On listener 8884, authentication is performed exclusively by the client certificate.
> Mosquitto uses the CN as the username
> (`use_identity_as_username true`). DynSec admin clients have
> **no password**. A client without a password cannot authenticate to any
> listener that requires a password, including 1883.

This means (tested on 20.11.2026 with Mosquitto 2.1.2 and
`mqtt-acl-verify`):

-   The certificate is bound to the identity: the CN determines the
    DynSec client; a different username in CONNECT is
    ignored.
-   DynSec authorizes Control API actions through the
    `role_security_manager` role.
-   There is no admin password that could be used on another listener.
    The admin is rejected on 1883, both with and
    without a password attempt.
-   Certificates from the server CA or a foreign CA are rejected during the TLS
    handshake on listener 8884; admin certificates are rejected on
    listeners that trust only the server CA.

The service sets neither username nor password in CONNECT.

**Disable an admin:** An admin certificate is disabled through DynSec,
using `deleteClient` (or by revoking all roles). An
existing connection is disconnected (“administrative action”),
and a new login with this certificate no longer has permissions. A
CRL is not used.

> **Decision – successor admin identities**
> DynSec knows only the name, not the certificate. If a
> disabled admin were recreated under the same name, the
> old certificate would regain full admin permissions (as with app certificates,
> Section 5.4). A successor therefore always receives the next
> number: `pmss-admin-2`, `pmss-admin-3`, or `pmss-breakglass-admin-2`.
> The Security Service reads its identity from the certificate and
> requires no configuration change for this.

> **Important: `disableClient` does not disable certificate authentication**
> The plugin checks the `disabled` flag only during password authentication
> (`plugins/dynamic-security/auth.c`), not for
> `use_identity_as_username` and not during ACL checks. An admin disabled with
> `disableClient` can still connect and retains
> **full Control API permissions** (tested 20.11.2026).

### 5.3 Planned file structure

Example structure; the actual paths and permissions must be determined during
implementation:

``` text
IOTstack/
└── volumes/
    ├── mqtt-server-ca/                # ca.crt only, mounted :ro in the Security Service
    │   └── ca.crt
    ├── mqtt-admin-ca/                 # ca.crt only, mounted :ro in Mosquitto
    │   └── ca.crt
    ├── mqtt-app-ca/                   # ca.crt only, mounted :ro in Mosquitto
    │   └── ca.crt
    ├── mosquitto/
    │   ├── config/
    │   ├── data/
    │   │   └── dynamic-security.json
    │   └── certs/                     # :ro
    │       ├── server.crt             # Server-CA, SAN DNS:mosquitto (8884)
    │       ├── server.key
    │       ├── server-ext.crt         # Server-CA, RSA, SAN mqtt.example.org (8883, 8885)
    │       └── server-ext.key
    └── phylax-mqtt-security-service/
        └── certs/                     # :ro
            ├── pmss-admin.crt         # Admin-CA, CN=pmss-admin
            └── pmss-admin.key

Außerhalb von IOTstack, offline gesichert:
    internal-ca/
    ├── server-ca/
    │   ├── ca.crt
    │   └── ca.key                     # nie in einen Container eingebunden
    ├── admin-ca/
    │   ├── ca.crt
    │   └── ca.key                     # nie in einen Container eingebunden
    ├── app-ca/
    │   ├── ca.crt
    │   └── ca.key                     # nie in einen Container eingebunden
    └── breakglass/
        ├── pmss-breakglass-admin.crt  # Admin-CA, CN=pmss-breakglass-admin
        └── pmss-breakglass-admin.key  # mounted only for emergency use
```

There is no DynSec admin password and therefore no password secret for
the Security Service.

Private keys must not be stored in the Git repository. File permissions and
container UID/GID must match the actual runtime configuration.

### 5.4 TLS for devices and applications (listeners 8883 and 8885)

**Server certificate:** TLS listeners 8883 and 8885 use their
own server certificate from the server CA (a separate `certfile` per
listener), separate from the internal certificate for 8884.

> **Decision**
> Clients reach the broker over TLS using the name
> **`mqtt.example.org`** (SAN `DNS:mqtt.example.org`). The
> server certificate has a **validity period of 12 months**.

Clients connect using this name, not the IP, otherwise
hostname verification fails. The name points to the broker in the local DNS (router);
it does not need to resolve publicly.

-   **RSA key type** (e.g. 2048 or 3072 bits): Tasmota's TLS stack
    (BearSSL) had problems with ECDSA certificates. With the
    own CA, the type can be chosen freely.
-   **Renewal:** Mosquitto reloads server certificates on SIGHUP,
    without restarting.
-   **Clients:** Applications receive the server CA certificate.
    Tasmota does not know the own CA and verifies the server by
    fingerprint; the fingerprint changes with every new
    server certificate, at least once a year.

> **Note: Annual renewal without Tasmota device downtime**
> Tasmota has two fingerprint slots, `MqttFingerprint1` and
> `MqttFingerprint2`, and accepts a server matching either one.
>
> 1. Issue the new server certificate well before expiration (e.g. 4 weeks), but do not deploy it yet.
> 2. Enter the new certificate's fingerprint in `MqttFingerprint2` on all Tasmota devices
>    using TLS (e.g. through TasmoFleet via
>    `Backlog`). `MqttFingerprint1` continues to contain the old one.
> 3. Deploy the new certificate in Mosquitto and send SIGHUP.
> 4. Then move the new fingerprint to `MqttFingerprint1`; the
>    old one is removed.
>
> Devices that were not reached in step 2 will lose their TLS connection after
> step 3 and need the new fingerprint through the
> HTTP API or on site. The expiration date is monitored (e.g. through
> certificate checks in monitoring).

**Listener 8883 – TLS with password:** Encryption for clients that
authenticate with a password (e.g. Tasmota devices using TLS). Permissions
are the same as on 1883; the password works on both listeners.

**Listener 8885 – app certificate only:** Applications with “TLS
required” authenticate exclusively with a certificate from the
App CA.

> **Decision**
> “TLS required” (Overview D-21) means: the client authenticates
> using an App CA certificate and has **no password**. This is the only way
> to enforce it at the broker, because DynSec does not bind a client
> to a listener. A client without a password cannot authenticate on 1883 or
> 8883 (tested 20.11.2026). TLS is optional for clients with passwords.

> **Decision – `use_subject_as_username` on the app listener**
> All listeners share the same DynSec configuration. With
> `use_identity_as_username`, an app certificate with
> `CN=pmss-admin` would authenticate as an admin. Listener 8885 therefore uses
> the **full subject** as the username
> (`use_subject_as_username true`, RFC 2253 order).

| App certificate (subject) | DynSec username |
|---|---|
| `/O=mqtt-apps/CN=homeassistant` | `CN=homeassistant,O=mqtt-apps` |
| `/O=mqtt-apps/CN=pmss-admin` (mis-issuance) | `CN=pmss-admin,O=mqtt-apps` – not `pmss-admin`, no admin permissions |

Usernames of certificate clients therefore always begin with `CN=`
and cannot collide with admin names or password clients.

**Naming rules** (enforced by the App CA and the Security Service,
Section 7.3):

| Rule | Purpose |
|---|---|
| The App CA issues only subjects of the form `/O=mqtt-apps/CN=<name>` | Consistent, predictable usernames |
| Names with the `pmss-` prefix and the `role_security_manager` role are reserved | Admin objects are not accessible through the API (second layer) |
| Password clients must not have `=` or `,` in the username | No password client can take the name of a certificate client |
| Certificate clients (`CN=…`) never receive a password | Otherwise the client could be used with a password on 1883/8883, defeating “TLS required” |
| Disabled names and subjects are not reused; successors receive a sequential number | Otherwise an old certificate would regain its permissions |

**Issuing app certificates:** Initially performed manually using a script
(template: `mqtt-acl-verify/testbroker-dynsec/make-certs.sh`), with the
App CA key kept offline.

> **Decision**
> Later, **TasmoFleet** will issue the app certificates. This is not
> part of v1 of the Security Service.

Consequences for this later development stage:

-   TasmoFleet needs its own signing key for this; the
    App CA key remains offline. **Before that development stage**, it will be
    decided whether to use an **intermediate CA under the App CA with a CRL**
    or an **independent TasmoFleet CA** (see note below).
-   Whoever holds this key can authenticate as any application,
    authenticate, but never as an admin (`use_subject_as_username`). The
    key, like MQTT credentials in TasmoFleet, is usable only by
    `security-admin`.
-   TasmoFleet enforces the naming rules (Subject `/O=mqtt-apps/CN=<name>`)
    TasmoFleet enforces when issuing certificates.
-   TasmoFleet must know disabled subjects and must not assign them again when
    do not issue them again (SEC-23).
-   TasmoFleet will continue to create the DynSec client `CN=<name>,O=mqtt-apps`
    through the Security Service's REST API, not directly on the broker.
-   The chain through an intermediate CA works on listener 8885
    with `cafile` = App CA (tested 20.11.2026 with Mosquitto 2.1.2).
    Condition: the application sends the intermediate CA, i.e. its
    certificate file contains the client certificate **and** intermediate CA.
    With only the client certificate, the TLS handshake fails.

> **Note: CRL in Mosquitto 2.1.2 (tested 20.11.2026)**
> With `crlfile`, Mosquitto checks only the client certificate itself
> (`X509_V_FLAG_CRL_CHECK`), not the certificates above it.
>
> | Case | Result |
> |---|---|
> | Intermediate CA revoked by App CA | ⚠️ Client certificates from the intermediate CA still authenticate |
> | Client certificate revoked by intermediate CA | ✅ rejected |
> | `crlfile` without CRL from issuing CA | ⚠️ **all** certificates from this CA are rejected |
> | New CRL, then SIGHUP | ✅ takes effect without restart |
> | CA removed from `cafile`, then SIGHUP | ⚠️ not effective until restart |
>
> Not tested: behavior with an expired CRL (`nextUpdate`). According to
> typical OpenSSL behavior, all certificates from this CA are then
> rejected; the CRL must be re-signed regularly.

**Open decision before the TasmoFleet development stage:**

| | Intermediate CA under the App CA with CRL | Own TasmoFleet CA |
|---|---|---|
| `cafile` on 8885 | App CA | App CA and TasmoFleet CA (adjust SEC-22: App CAs only) |
| Revoke an individual certificate | Intermediate CA CRL plus SIGHUP, or `deleteClient` and new subject | `deleteClient` and new subject (SEC-23) |
| TasmoFleet key compromised | Revoking the intermediate CA has no effect (see note): replace App CA, reissue all app certificates, restart | Remove TasmoFleet CA from `cafile`, restart; App CA certificates remain valid |
| Operation | `crlfile` needs CRLs from the App CA **and** intermediate CA, re-signed regularly; TasmoFleet must deliver its CRL to the broker | No CRL operations |
| To check | Restrict intermediate CA `nameConstraints` to its own `O=` so a stolen key can issue only TasmoFleet subjects | Both CAs issue `O=mqtt-apps`; a stolen TasmoFleet key can also impersonate App CA subjects until the CA is removed |

**Disabling** an app certificate is done as with admins, using `deleteClient`
or revoking roles, not with `disableClient` (Section 5.2).
Through the REST API, this is done with `DELETE /api/v1/clients/{username}`;
`enable`/`disable` are rejected for certificate clients (A-10,
Section 7.3). DynSec knows only the subject, not the certificate.
If a client is recreated under the same subject after being disabled because
of compromise, the old certificate also regains its
permissions (tested 20.11.2026). The new certificate therefore always gets
a new subject, e.g. `CN=homeassistant-2`. Without a CRL, this is
the only way to permanently disable a compromised certificate.

## 6. Mosquitto Dynamic Security

### 6.1 Plugin and persistence

The plugin is already present in the existing container:

``` text
/usr/lib/mosquitto_dynamic_security.so
```

The persistent configuration is to be located here:

``` text
Host:      ~/IOTstack/volumes/mosquitto/data/dynamic-security.json
Container: /mosquitto/data/dynamic-security.json
```

The `/mosquitto/data` directory is already mounted persistently.

### 6.2 Initialization

The DynSec configuration is explicitly initialized before enabling the plugin.
For Mosquitto 2.1.x, do not rely unchecked on automatic creation of a
default configuration when the file is missing. The automatically generated
default configuration can create default accounts such as `admin` and
`democlient`. Explicit initialization is therefore preferred to avoid
unintended demo credentials.

`mosquitto_ctrl dynsec init` always creates an admin **with a password** and
the `admin` role. The role name is fixed in Mosquitto 2.1.2.
In addition to `$CONTROL/dynamic-security/#` and `$SYS/#`, the `admin` role
also contains `publishClientReceive #`, `subscribePattern #`, and
`unsubscribePattern #`; the admin could therefore read all application topics,
including backups.

> **Decision – offline bootstrap**
> The admin from `dynsec init` is only a **bootstrap admin**
> (`dynsec-bootstrap`). It is used exclusively in a temporary
> broker container **without a network** and is deleted there at the end,
> along with the `admin` role. After that, only the admins
> `pmss-admin` and `pmss-breakglass-admin` exist, without passwords and with the
> `role_security_manager` role.

Procedure (successfully tested on 20.11.2026 with Mosquitto 2.1.2):

1.  Initialize; `mosquitto_ctrl` prompts for a one-time password:

    ``` bash
    docker run --rm -it --network none \
      -v ~/IOTstack/volumes/mosquitto/data:/mosquitto/data \
      eclipse-mosquitto:2.1.2 \
      mosquitto_ctrl dynsec init /mosquitto/data/dynamic-security.json \
      dynsec-bootstrap
    ```

2.  Start a temporary broker with the same image:
    `docker run --rm --network none`, data directory mounted,
    custom minimal configuration:

    ``` ini
    per_listener_settings false
    allow_anonymous false
    listener 1883 127.0.0.1
    plugin /usr/lib/mosquitto_dynamic_security.so
    plugin_opt_config_file /mosquitto/data/dynamic-security.json
    ```

3.  In the temporary container, run the following in sequence using
    `mosquitto_ctrl -h 127.0.0.1 -u dynsec-bootstrap -P … dynsec`
    (stdin `</dev/null`, otherwise `createClient` prompts for a password):

    ``` text
    setDefaultACLAccess publishClientSend deny
    setDefaultACLAccess publishClientReceive deny
    setDefaultACLAccess subscribe deny
    setDefaultACLAccess unsubscribe allow
    createRole role_security_manager
    addRoleACL role_security_manager publishClientSend $CONTROL/dynamic-security/# allow
    addRoleACL role_security_manager publishClientReceive $CONTROL/dynamic-security/# allow
    addRoleACL role_security_manager subscribePattern $CONTROL/dynamic-security/# allow
    addRoleACL role_security_manager publishClientReceive $SYS/# allow
    addRoleACL role_security_manager subscribePattern $SYS/# allow
    createClient pmss-admin
    addClientRole pmss-admin role_security_manager
    createClient pmss-breakglass-admin
    addClientRole pmss-breakglass-admin role_security_manager
    createRole role_legacy
    addRoleACL role_legacy publishClientSend # allow
    addRoleACL role_legacy publishClientReceive # allow
    addRoleACL role_legacy subscribePattern # allow
    createClient legacy-shared-user
    addClientRole legacy-shared-user role_legacy
    addClientRole dynsec-bootstrap role_security_manager
    deleteRole admin
    deleteClient dynsec-bootstrap
    ```

    Order at the end: the bootstrap admin first receives
    `role_security_manager` so that it can still run `deleteClient` on itself
    after `deleteRole admin`.

4.  Stop the temporary broker. The one-time password is then useless.

5.  Import the existing user's password hash while no broker
    is running (DynSec reads the file only at startup and overwrites it
    on every change):

    ``` bash
    sudo python3 import-pwfile.py \
      ~/IOTstack/volumes/mosquitto/pwfile/pwfile \
      ~/IOTstack/volumes/mosquitto/data/dynamic-security.json \
      legacy-shared-user
    ```

    The script (`mqtt-acl-verify/testbroker-dynsec/import-pwfile.py`)
    imports only `$7$` hashes and only for clients that have already been created,
    and writes the file in place (ownership and permissions
    remain unchanged). The `migrate_to_dynsec.py` shipped with Mosquitto 2.1
    is **not** used: it overwrites `mosquitto.conf`, creates its own roles,
    and sets `publishClientReceive` to allow.

Result: `dynamic-security.json` contains `pmss-admin` and
`pmss-breakglass-admin` without passwords, `legacy-shared-user` with its
existing password hash and the `role_legacy` role, the roles
`role_security_manager` and `role_legacy`, and default-deny.
The production broker starts directly with this file. At no
point is an admin with a password reachable over a network.

**Note on scripts:** `mosquitto_ctrl` exits with code 0 even on
`Not authorized`. Scripts must check the output.

### 6.3 Plugin configuration

Production broker configuration (corresponds to the test broker
`mqtt-acl-verify/testbroker-dynsec` tested on 20.11.2026; there,
port 8886 corresponds to port 8884, 8883 to port 8883, and 8887 to port
8885):

``` ini
per_listener_settings false
allow_anonymous false

plugin /usr/lib/mosquitto_dynamic_security.so
plugin_opt_config_file /mosquitto/data/dynamic-security.json

# Devices and applications (username/password)
listener 1883

# Internal admin access: Admin CA certificate only, username = CN
listener 8884
cafile   /mosquitto/admin-ca/ca.crt
certfile /mosquitto/certs/server.crt
keyfile  /mosquitto/certs/server.key
require_certificate true
use_identity_as_username true

# From Phase 5: TLS with password
listener 8883
certfile /mosquitto/certs/server-ext.crt
keyfile  /mosquitto/certs/server-ext.key
tls_version tlsv1.2

# From Phase 5: applications using App CA certificate only,
# username = subject, e.g. "CN=homeassistant,O=mqtt-apps"
listener 8885
cafile   /mosquitto/app-ca/ca.crt
certfile /mosquitto/certs/server-ext.crt
keyfile  /mosquitto/certs/server-ext.key
require_certificate true
use_subject_as_username true
tls_version tlsv1.2
```

> **Decision**
> Plugin configuration as tested: `per_listener_settings false`,
> `plugin` is global. `plugin_load`/`plugin_use` will be used only once
> equivalence with Mosquitto 2.1.2 has been tested.

`require_certificate`, `use_identity_as_username`,
`use_subject_as_username` and `tls_version` apply per listener despite
`per_listener_settings false`. All listeners use the same DynSec
configuration.

`cafile` on listener 8884 is the **Admin CA**, not the Server CA. The
server certificate comes from the Server CA. This combination has been
tested.

The final configuration is checked with
`mosquitto --test-config` before restarting.

`allow_anonymous false` remains active. It does **not** prevent
a certificate from the Admin CA with an unknown CN from connecting (the
username comes from the CN); however, such a client has no
permissions. `password_file` and `acl_file` are removed or disabled after
successful migration.

### 6.4 Data model

Dynamic Security has three central object types:

| Object | Purpose | Example |
|---|---|---|
| Client | MQTT identity with username, password, and optional client ID | `wz-steckdose-tv` (Tasmota topic, D-15) |
| Group | Groups clients with shared roles | `tf_group_tasmota` |
| Role | Contains topic ACLs | `tf_role_tasmota` |

Admin role:

-   `role_security_manager`: only `$CONTROL/dynamic-security/#`
    (send, receive, subscribe) and `$SYS/#` (receive, subscribe), no
    access to application topics. Replaces the `admin` role from
    `dynsec init`.

Usernames:

-   Password clients: without `=` and `,` (e.g. Tasmota topic,
    `legacy-shared-user`).
-   Certificate clients (listener 8885): app certificate subject,
    e.g. `CN=homeassistant,O=mqtt-apps`, no password.
-   Admins: `pmss-admin`, `pmss-breakglass-admin`, and their successors
    `pmss-admin-<n>`, `pmss-breakglass-admin-<n>` (reserved).
-   Tasmota devices: username = Tasmota `Topic` (Overview D-15). The
    topic must not start with `pmss-` or contain `=` or `,`;
    TasmoFleet blocks devices with an invalid topic.

> **Decision – Objects managed by the Security Service**
> - **Roles and groups** of the Security Service have the prefix
>   **`tf_`**, e.g. `tf_role_tasmota`, `tf_group_tasmota`.
> - **Clients** keep their names (no prefix, so `cmnd/%u/#`
>   works) and are marked in `textdescription`:
>   `managed-by: pmss`.
> - The Security Service modifies, deletes, and associates only managed
>   objects. It may read all objects.
> - `legacy-shared-user` and `role_legacy` remain **without**
>   a marker or prefix and are changed only through break-glass
>   and deleted during cleanup (Section 9, Phase 7).

Anything created with `mosquitto_ctrl` is therefore automatically protected from
the Security Service. The prefix and marker are configurable in the service
(environment variables), so the interface is not tied to
TasmoFleet (Overview question 16).

Profiles with `%u` (e.g. `cmnd/%u/#`) are intended only for password clients;
the subject name of a certificate client is not suitable
as a topic level.

Proposed future roles (managed, with prefix):

-   `tf_role_tasmota`
-   `tf_role_amsreader`
-   `tf_role_smart_irrigation`
-   `tf_role_mqtt_viewer`

> **Decision – role per Tasmota device (Specification S-7)**
> GroupTopic, FallbackTopic, and Discovery do not fit in a profile with
> `%u`. They are placed in a separate role for each device named
> `tf_role_dev_<mac>`: MAC in lowercase, 12 hexadecimal characters without
> separators, e.g. `tf_role_dev_a4cf12345678`. The topic is stored in
> `textname`. If the topic changes, a new client is created; the
> device role remains.

The final topic filters are not defined in this draft.
They must be derived from the topic structures actually used and the
required read/write flows.

### 6.5 Default-deny

The target model follows the **deny by default** principle: actions not
explicitly allowed are denied.

DynSec distinguishes, among others:

-   `publishClientSend`
-   `publishClientReceive`
-   `subscribeLiteral`
-   `subscribePattern`
-   `unsubscribeLiteral`
-   `unsubscribePattern`

The plugin's defaults are not automatically deny for all ACL types.
Therefore, the desired defaults must be explicitly checked and set.
In particular, `publishClientReceive` and `unsubscribe` default to allow.
The defaults are set during bootstrap (Section 6.2): `publishClientSend`,
`publishClientReceive`, and `subscribe` deny, `unsubscribe` allow.

During migration, a temporary legacy role is initially
needed to represent the existing MQTT user's previous broad access.
This role is explicitly only a transition and will later be removed or restricted.

> **Decision – `role_legacy`**
> The legacy user can do everything as before, but cannot access `$SYS/#` or
> `$CONTROL/#`.

| ACL type | Topic | Effect |
|---|---|---|
| `publishClientSend` | `#` | Publish to all application topics |
| `publishClientReceive` | `#` | Receive all application topics, including `stat/+/FILEDOWNLOAD` (as today) |
| `subscribePattern` | `#` | Subscribe to all application topics |

The `#` wildcard does not cover topics beginning with `$`. `$SYS/#`
and `$CONTROL/#` therefore remain prohibited without an additional rule (tested
20.11.2026: subscription to `$SYS/…` rejected, no access to the
Control API).

### 6.6 Topic inventory and logging

> **Decision**
> Observation and restriction are kept separate. The topic inventory is
> collected for **one week** after the functional test (Phase 4), in parallel
> with Phases 5 and 6; debug logging is then disabled.
> Restrictions are introduced only in Phase 7, after the Security Service, because
> rules based on client ID without individual credentials are not a
> security boundary. The log destination is a centralized Syslog service, e.g. the
> **phylax-syslog-service**;
> `mqtt-acl-verify inventory` evaluates its files.

**Log destination:** Mosquitto continues to write to stdout (`log_dest stdout`).
Docker forwards the output to the
phylax-syslog-service using the `syslog` logging driver:

``` yaml
services:
  mosquitto:
    logging:
      driver: syslog
      options:
        syslog-address: "udp://<host-des-phylax-syslog-service>:514"
        syslog-format: rfc5424
        tag: mosquitto
```

-   The address is resolved by the Docker daemon on the host, not by the
    container; a Compose service name does not work here.
-   UDP does not block the container if the Syslog service is not
    reachable. Individual lost lines are not critical for the inventory.
-   `docker logs` remains available through Docker's dual logging.
-   The driver is enabled during the planned restart in Phase 3
    (`docker compose up -d` recreates the container).

**Enable and disable debug logging:** `log_type` can be changed without
restarting by sending SIGHUP (tested 20.11.2026):

``` bash
# enable: set "log_type all" in mosquitto.conf, then
docker compose kill -s SIGHUP mosquitto
# after one week: restore the normal log_type lines, then
docker compose kill -s SIGHUP mosquitto
```

**Debug log contents:** Client IDs, usernames, IP addresses, and
topics from PUBLISH and SUBSCRIBE packets; no payloads or
passwords. The files are protected like configuration data.

**Analysis:** `mqtt-acl-verify inventory <log> -p -u -x` reads the
phylax-syslog-service files. The parser locates Mosquitto lines
regardless of the prepended Syslog header and also accepts the tab
before the topics of a SUBSCRIBE as `#011` or a space
(mqtt-acl-verify, test `test_parse_syslog_lines`). Requirement: the
phylax-syslog-service writes each message as one line and otherwise leaves
the message text unchanged.

## 7. Phylax MQTT Security Service – Go

### 7.1 Responsibilities

The Phylax MQTT Security Service is a standalone Go application and
is not part of the Mosquitto broker.

Responsibilities:

-   Provide REST endpoints for managing MQTT clients, groups, and
    roles.
-   Validate input and authorize API callers.
-   Translate DynSec commands into the MQTT Control API's JSON format.
-   Send commands to Mosquitto over a persistent MQTT connection.
-   Evaluate responses and return them as REST responses.
-   Log errors, changes, and administrative actions,
    with before and after state.
-   Export the current state of managed objects (for diff,
    drift report, and backup in TasmoFleet).
-   Handle passwords and private keys securely.

Not the Security Service's responsibility: desired state,
diff, approval, drift report, and backup before applying. The
service stores no state (read-only filesystem, no
database, no access to `dynamic-security.json`); these tasks
belong to TasmoFleet (Overview 7.3).

Proposed package structure (non-binding):

``` text
phylax-mqtt-security-service/
├── cmd/phylax-mqtt-security-service/   # main: Konfiguration, Start, Graceful Shutdown
├── internal/api/                # net/http-Handler, Routing, Validierung
├── internal/auth/               # Bearer-Token-Prüfung (JWT, JWKS, Scopes)
├── internal/dynsec/             # Kommando-/Antwort-Typen, Korrelation, Timeouts
├── internal/mqttclient/         # Paho-Verbindung, TLS-Konfiguration, Reconnect
├── internal/audit/              # audit logging with slog
├── Dockerfile
├── test/integration/            # Integrationstests, Compose-Dateien, Realm-JSON (Keycloak), Blueprint (authentik)
├── go.mod
└── go.sum
```

### 7.2 MQTT communication

The service uses **Eclipse Paho Go** and connects to:

``` text
mqtts://mosquitto:8884
```

It uses **MQTT 5** via `github.com/eclipse/paho.golang`
with the **`autopaho`** package. `autopaho` handles connection establishment
and reconnect; a separate reconnect layer directly over `paho` is
is not implemented. After a reconnect, `autopaho` does **not**
subscribe to the response topic by itself (tested, see below); the service
therefore subscribes to it in `OnConnectionUp`.
A fallback to MQTT 3.1.1 (`paho.mqtt.golang`) is not planned,
since Mosquitto 2.1.2 fully supports MQTT 5. The
TLS configuration from Section 5.2 (`*tls.Config`) is passed directly to the
Paho client. Username and password remain empty; the
identity is derived from the client certificate's CN.

Planned Control topics:

``` text
Request:  $CONTROL/dynamic-security/v1
Response: $CONTROL/dynamic-security/v1/response
```

The service subscribes to the response topic and publishes JSON commands
to the request topic. Responses contain a `responses` list with
command results and, where applicable, error details. For concurrent
REST requests, the service must correctly correlate responses and handle timeouts;
a single MQTT response channel must not cause
incorrect correlation for simultaneous requests.

Correlation in Go (conceptual):

-   Each command receives a unique `correlationData` ID in the
    DynSec JSON, always as a string (UUID). The plugin returns it in the
    response for the respective command, including on errors (tested,
    see below).
-   Pending requests are held in a `sync.Mutex`-protected
    map `correlationID → chan Response`.
-   Paho's response handler decodes the message with
    `encoding/json` and delivers each partial response to the matching
    channel.
-   The REST handler waits with `select` for a response,
    `ctx.Done()` (client disconnect), or timeout
    (`context.WithTimeout`) and always removes the map entry
    afterwards.
-   Responses without a correlation ID or with an unknown one are
    logged and discarded. This is not an error: the plugin
    sends every response to **all** subscribers of the response topic,
    including responses for `pmss-breakglass-admin` (`mosquitto_ctrl`)
    or a second service instance.
-   The MQTT 5 properties `Response Topic` and `Correlation Data`
    are not used; the plugin does not evaluate them.

> **Note: `correlationData` in Mosquitto 2.1.2 (tested 21.11.2026)**
> Verified with `mqtt-acl-verify` (`tests/test_dynsec_control.py`) and in the
> source code (`src/control_common.c`).
>
> | Case | Result |
> |---|---|
> | Multiple commands with `correlationData` in one request | ✅ Each response carries its own value, in batch order |
> | Error response (`Client not found`, `Client already exists`) | ✅ with `correlationData` |
> | UUID, empty string | ✅ returned unchanged |
> | Without `correlationData` | Field is absent from the response |
> | `correlationData` is not a string (e.g. number) | ⚠️ Error `Invalid correlationData data type.` **without** `correlationData`; the **remaining commands in the batch are not executed** |
> | Payload is not JSON, `commands` is not an array | ⚠️ Error without `correlationData` |
> | MQTT 5 properties `Response Topic`, `Correlation Data` | ⚠️ ignored; response always on `$CONTROL/dynamic-security/v1/response`, without properties |
> | Second admin subscribed to the response topic | ⚠️ receives **every** response, including the service's |
>
> A request whose response does not carry `correlationData` ends in a
> timeout for the service.

> **Note: `autopaho` on reconnect and pending requests (tested 21.11.2026)**
> Verified with `paho.golang` v0.23.0 and Mosquitto 2.1.2
> (`mqtt-acl-verify`, `probes/autopaho-reconnect/`). A TCP proxy
> disconnects without DISCONNECT or discards the broker's responses.
>
> | Case | Result |
> |---|---|
> | 20 concurrent requests on one response topic | ✅ all correctly correlated via `correlationData` |
> | Reconnect, Clean Session, subscribed only once after startup | ❌ **no more responses**; `autopaho` does not resubscribe |
> | Reconnect, Abonnement in `OnConnectionUp` | ✅ Antworten kommen an |
> | Reconnect, `SessionExpiryInterval` 60 s, subscribed once | ✅ `SessionPresent`, the broker session retains the subscription |
> | `Publish` without a connection | ⚠️ immediate `ConnectionDownError`, does not wait for reconnect (`AwaitConnection` waits) |
> | Connection drops after broker executes `createClient` (PUBACK and response lost), Clean Session | ⚠️ `Publish` does **not** end with the disconnect, only with the context timeout; the response is lost; the client **was created** |
> | Same with `SessionExpiryInterval` 60 s | ⚠️ paho repeats the PUBLISH after reconnect, Mosquitto **executes the command a second time**; only the response to the repeated command arrives: `Client already exists` |

> **Decision A-9 – MQTT connection and pending requests (Specification S-13)**
> Derived from the tests above:
> - **Clean Session:** `CleanStartOnInitialConnection true`,
>   `SessionExpiryInterval` 0. DynSec commands are not idempotent;
>   with a session, an unconfirmed request would be repeated after
>   reconnect and executed a second time.
> - **Subscribe in `OnConnectionUp`,** on every connection. The service
>   accepts Control API requests only after the subscription has been
>   confirmed.
> - **Timeout per request** via `context.WithTimeout`; a
>   disconnection does not terminate an ongoing `Publish`.
> - **Without a connection** (`ConnectionDownError`), the service waits
>   with `AwaitConnection` only until the request timeout and
>   otherwise responds with `broker_unavailable`, without sending the command
>   later.
> - **Password changes** cannot be read back (no hash in
>   `getClient`); if the response is missing, the service always responds
>   with `broker_timeout`. When creating a client with a generated password,
>   reading the client back is sufficient; the sent password is returned with
>   `201`.
> - **After a timeout, the state is unknown:** the command may have
>   been executed. For modifying requests, the service reads the
>   object back (`getClient`/`getGroup`/`getRole`). If it matches the
>   target, the request is considered successful; otherwise, or if
>   readback fails, it responds with `broker_timeout` and
>   records the uncertain state in the audit log.
> - **No automatic retries** of modifying commands.

Example of a DynSec command:

``` json
{
  "commands": [
    {
      "command": "createClient",
      "username": "wz-steckdose-tv",
      "password": "replace-with-generated-secret",
      "correlationData": "b3f1c2e0-..."
    }
  ]
}
```

The plugin API reference is authoritative for field names and
response format. The Go application represents these as typed structs
and must not invent its own, divergent DynSec semantics.

In the REST API, fields from DynSec retain their DynSec names
(`textname`, `rolename`, `acltype` …). The service's own fields are
in camelCase (`etag`, `authType`, `exportedAt`, `apiVersion`,
`warnings`). (Spezifikation S-8)

### 7.3 REST interface

> **Decision – interface specification**
> The REST API implements the “MQTT Security Service API v1” interface
> specification (`mqtt-security-service-api-v1`).
> It defines paths, fields, status codes, error codes, `ETag` rules, and
> examples authoritatively. This section describes the implementation
> in PMSS. In case of discrepancies, the specification takes precedence.

The REST API is implemented with `net/http` and `http.ServeMux`. The
standard library's method and path patterns cover the following
resources without an external router.

> **Decision**
> Version 1 of the REST API covers the **basic DynSec functions**:
> clients, groups, roles, ACLs, and their associations. Each endpoint
> corresponds to a DynSec command or a small, fixed sequence of
> commands.

REST scope v1 (all paths with prefix `/api/v1/`, Specification S-9):

| Method | Endpoint | Purpose | DynSec command |
|---|---|---|---|
| `GET` | `/api/v1/info` | API version, prefixes, marker, password rule, reserved names, limits (Specification 4.1) | – (from configuration) |
| `GET` | `/api/v1/export` | All managed objects (clients, groups, roles with ACLs and associations) as one JSON | `listClients`, `listGroups`, `listRoles` (each with details) |
| `GET` | `/api/v1/clients` | List clients | `listClients` |
| `POST` | `/api/v1/clients` | Create client (optionally with role/group, optionally with password) | `createClient` (+ `addClientRole` / `addGroupClient`) |
| `GET` | `/api/v1/clients/{username}` | Client details | `getClient` |
| `PATCH` | `/api/v1/clients/{username}` | Change text name (`textdescription` is the marker and cannot be changed) | `modifyClient` |
| `POST` | `/api/v1/clients/{username}/password` | New password: provided by caller or generated by PMSS | `setClientPassword` |
| `POST` | `/api/v1/clients/{username}/enable` | Enable client (password clients only, A-10) | `enableClient` |
| `POST` | `/api/v1/clients/{username}/disable` | Disable client (password clients only, A-10) | `disableClient` |
| `DELETE` | `/api/v1/clients/{username}` | Delete client | `deleteClient` |
| `POST` | `/api/v1/clients/{username}/roles` | Assign role (optionally with `priority`) | `addClientRole` |
| `DELETE` | `/api/v1/clients/{username}/roles/{role}` | Revoke role | `removeClientRole` |
| `GET` | `/api/v1/groups` | List groups | `listGroups` |
| `POST` | `/api/v1/groups` | Create group | `createGroup` |
| `GET` | `/api/v1/groups/{group}` | Group details | `getGroup` |
| `DELETE` | `/api/v1/groups/{group}` | Delete group | `deleteGroup` |
| `POST` | `/api/v1/groups/{group}/clients` | Add client to group | `addGroupClient` |
| `DELETE` | `/api/v1/groups/{group}/clients/{username}` | Remove client from group | `removeGroupClient` |
| `POST` | `/api/v1/groups/{group}/roles` | Assign role to group | `addGroupRole` |
| `DELETE` | `/api/v1/groups/{group}/roles/{role}` | Revoke role from group | `removeGroupRole` |
| `GET` | `/api/v1/roles` | List roles | `listRoles` |
| `POST` | `/api/v1/roles` | Create role, optionally with ACL list | `createRole` (with `acls`) |
| `GET` | `/api/v1/roles/{role}` | Role details including ACLs | `getRole` |
| `DELETE` | `/api/v1/roles/{role}` | Delete role | `deleteRole` |
| `POST` | `/api/v1/roles/{role}/acls` | Add ACL | `addRoleACL` |
| `PUT` | `/api/v1/roles/{role}/acls` | Replace complete ACL list of role | `modifyRole` with `acls` |
| `DELETE` | `/api/v1/roles/{role}/acls` | Remove ACL (ACL type and topic in body) | `removeRoleACL` |

Endpoints from PMSS v1 that are not in the specification (list endpoints,
individual ACLs via `POST`/`DELETE`, `PATCH`, `enable`/`disable`) are
retained, also under `/api/v1/`. TasmoFleet does not use them.

**Name validation:** The service enforces the naming rules
from Section 5.4:

-   `POST /api/v1/clients` rejects names with the `pmss-` prefix, as well as
    password clients with `=` or `,` in the name.
-   Clients whose name begins with `CN=` are created without a password.
- A password provided during creation is rejected with
    `422 validation_failed`;
    `POST /api/v1/clients/{username}/password` with
    `409 certificate_client`.
-   All endpoints reject modifications to `pmss-*` and
`role_security_manager`, including assignment of this role.

**Managed objects:**

-   `POST /api/v1/clients` sets the `managed-by: pmss` marker in
    `textdescription`. `POST /api/v1/roles` and `POST /api/v1/groups`
    require the `tf_` prefix.
-   Modifying endpoints for clients without a marker or roles and
    groups without a prefix return `403`, e.g. for
    `legacy-shared-user` and `role_legacy`.
-   Associations are possible only between managed objects: a
    managed client cannot be assigned an unmanaged role (e.g.
    `role_legacy`).
-   `GET` endpoints return all objects and indicate whether an object
    is managed.

> **Decision – passwords**
> - The caller **may** provide a password
>   (`POST /api/v1/clients`, `POST /api/v1/clients/{username}/password`).
>   If omitted, the Security Service generates one using `crypto/rand`.
> - Every password, including a provided one, consists only of
>   `A–Z a–z 0–9` and is exactly **24 characters** long. Other passwords are rejected
>   with `422`.
> - A generated password appears exactly once in the response
>   (`Cache-Control: no-store`) and is not stored or
>   logged.

Rationale for the character alphabet: Tasmota receives the password via
`Backlog MqttUser <user>; MqttPassword <passwort>`. `;` separates the
commands, and spaces separate command and value; neither may occur in the password.
Tasmota requires at least 5 characters and imposes no maximum length in
the `MqttPassword` command or the web form
(Tasmota source code `xdrv_02_9_mqtt.ino`, verified 20.11.2026). 62
characters over 24 positions yield around 142 bits.

A provided password is intended for cases where the password
is already fixed (e.g. on a device that cannot be configured remotely).
Normally, the Security Service generates the password; TasmoFleet
transfers it to the device and discards it afterwards (Overview question 15).

> **Decision A-10 – `enable`/`disable` for certificate clients (Specification Section 4)**
> `disableClient` affects only password authentication (Section 5.2).
> For clients whose name begins with `CN=`, the service rejects
> `POST /api/v1/clients/{username}/disable` and
> `POST /api/v1/clients/{username}/enable` mit
> `409 certificate_client` without sending a command to the broker
>   without sending a command to the broker. A certificate client is disabled only via
>   `DELETE /api/v1/clients/{username}`; a successor receives
>   a new subject (Section 5.4). `enable` and `disable` remain available
>   for password clients. Mapping `disable` to
>   revoking roles was rejected: it would hide state that
>   `enable` would need to restore, and the service stores no
>   state. The specification adopted this solution
>   (Section 4, “Variant A”).

> **Note: DynSec Control API behavior (tested 20.11.2026, Mosquitto 2.1.2)**
>
> | Case | Result |
> |---|---|
> | `addRoleACL` without `allow` | ⚠️ A **Deny** rule is created (`allow: false`) |
> | `modifyRole` with complete `acls` list | ✅ Replaces all ACLs of the role in one command |
> | `modifyRole` with an entry containing unknown `acltype` | ⚠️ No error: the entry is silently omitted and the rest is applied |
> | Multiple commands, the second fails | ⚠️ The first remains effective; no transaction |
> | Same `acltype` + `topic` combination twice | Rejected (“ACL with this topic already exists”) |

**ACL fields (Overview question 29):**

| Field | Rule | Reason |
|---|---|---|
| `acltype` | Required; only `publishClientSend`, `publishClientReceive`, `subscribeLiteral`, `subscribePattern`, `unsubscribeLiteral`, `unsubscribePattern` | `modifyRole` would silently omit unknown types |
| `topic` | Required | Together with `acltype`, the key of an ACL |
| `allow` | **Required**, no default | Without `allow`, DynSec creates a Deny rule |
| `priority` | Optional, Standard 0, Bereich −100000 bis 100000 | Wie DynSec |

If a deny rule does not have a higher priority than an allow rule
of the same type in the same role, the response includes
a warning: at equal priority, the order is not
defined (Overview 4, FILEDOWNLOAD). Role assignment to clients
and groups optionally accepts a `priority` (DynSec default −1).

**Create role with ACLs (`POST /api/v1/roles`, Specification S-6):**
If `acls` is provided, the service validates each entry as for
`PUT …/acls`, sends `createRole` with the complete list, and reads
the role back via `getRole`. If the actual state differs, it deletes
the role again (`deleteRole`) and responds with
`500 readback_mismatch`; if deletion fails, it responds with
`502 partial_failure` and `"roleExists": true`.

**Replace ACL list (`PUT /api/v1/roles/{role}/acls`):** The service
validates each entry according to the table above, sends `modifyRole` with
the complete list, and then reads the role back via `getRole`.
If the actual state differs from the submitted list, the service responds
with an error and logs the discrepancy. The role thus changes from the
old state to the new state in one step.
`POST` and `DELETE` for individual ACLs are retained.

**Concurrent modifications (`ETag`/`If-Match`):** `GET` responses for
clients, groups, and roles contain an `ETag`: a hash over the
fields belonging to the object (Specification 3.2, S-4):

| Object | Fields in ETag |
|---|---|
| Client | `username`, `textname`, `textdescription`, `disabled`, `roles` |
| Group | `groupname`, `textname`, `roles`, `clients` |
| Role | `rolename`, `textname`, `acls` |

Group membership of a client belongs to the group; `groups` is shown on
the client but is not included in its ETag. Thus each association changes
exactly one ETag, namely that of the object in the path. The
password hash is not included; a password change does not change the ETag
(S-5). Lists are sorted as in the export for the calculation.

`getClient` and `listClients` (including with `verbose`) do not return a
password hash; the output of `getClient` is identical before and after
`setClientPassword` (tested 21.11.2026, `mqtt-acl-verify`).
S-5 is thereby confirmed against the broker. DynSec returns `disabled` only when
it is set (`true`); for the ETag, a missing field is treated as
`false`.

Modifying requests for an existing object require `If-Match` with
this value. Before the modification, the service reads the object,
recalculates the hash, and if it differs responds with
`412 Precondition Failed` without changing anything; if `If-Match` is
missing, it responds with `428 Precondition Required`. The service needs
no storage for this. A short time window remains between checking and
modification; DynSec itself has no conditional updates.

**Response for associations (Specification S-10):**
`POST /api/v1/clients/{username}/roles`,
`POST /api/v1/groups/{group}/clients` and
`POST /api/v1/groups/{group}/roles` respond with `200`, the modified
object (client or group) in the body, and the new `ETag`. The
corresponding `DELETE` requests respond with `204` and the new
`ETag` header.

**Export (`GET /api/v1/export`):** returns all managed objects
(Section 6.4) in one JSON object with the lists `clients`, `groups`, and
`roles`, together with `exportedAt` and `apiVersion` (Specification 4.2, S-3).
Unmanaged objects (e.g. `legacy-shared-user`, `role_legacy`,
admins) are not included.

-   Each object carries its `etag`. All fields are always present;
    empty lists as `[]`, `priority` also when it has the default value.
-   Clients additionally have `authType`: `certificate` for names with
    `CN=`, sonst `password`.
-   Sorting is by Unicode code points: objects by name,
    associations by name, ACLs by `acltype` and `topic`. The service
    sorts them itself, regardless of the order in which DynSec
    responds.

TasmoFleet uses the export for diff, drift report, and backup
before applying changes. Scope `read`: `security-admin` through TasmoFleet (Token
Exchange) and read-only service accounts.

**Info (`GET /api/v1/info`, Specification 4.1, S-2):** returns
`apiVersion`, implementation name and version, broker product and
version, prefixes for roles and groups, the client marker,
password rule, reserved names, and
`limits.maxRequestBytes`. The values come from the service configuration
(environment variables for prefix and marker, Section
6.4). Scope `read`.

**Error responses (Specification 3.4, 3.5, S-1):** Each error is returned as
`application/problem+json` according to RFC 9457, with `status`,
`code`, and `title`, and for `422` additionally `errors` with JSON Pointer. The
error codes and their status codes are defined in the specification
(u. a. `invalid_token`, `insufficient_scope`, `not_managed`,
`reserved_name`, `validation_failed`, `unknown_role`,
`certificate_client`, `precondition_failed`, `precondition_required`,
`readback_mismatch`, `partial_failure`, `broker_unavailable`,
`broker_timeout`). `type` is a URI of the service, e.g. pointing to the
error list in the repository. `detail` never contains passwords, tokens, or
password hashes. For `401` and `403 insufficient_scope`, the
service sets `WWW-Authenticate` according to RFC 6750.

**Formats (Specification 3.1, S-12):** Timestamps use RFC 3339 in
UTC. Path parameters are URL-encoded (`CN%3Dhomeassistant%2CO%3Dmqtt-apps`);
the service decodes them with `r.PathValue`. Responses to modifying
requests with a body contain `warnings` (the only case so far:
a deny rule without higher priority). A provided password is not
included in the response (`"passwordGenerated": false`).

Not part of v1 and still available only through `mosquitto_ctrl` (break-glass,
Section 7.5):

-   Default ACL access (`setDefaultACLAccess`) – security-critical
    base setting for default-deny.
-   Anonymous group (`setAnonymousGroup`).
-   Changes to the admin clients `pmss-admin` and
    `pmss-breakglass-admin` and to `role_security_manager` itself.

Additionally planned: a `GET /healthz` for the container health check,
internal only, with no sensitive information and no version segment in the path
(S-9).

Requirements for the HTTP server:

-   `http.Server` with `ReadHeaderTimeout`, `ReadTimeout`,
    `WriteTimeout` and `IdleTimeout`.
-   Limit the request body size (`http.MaxBytesReader`) to
    at least 1 MiB, configurable; the value is returned by
    `GET /api/v1/info` (`limits.maxRequestBytes`). Above that,
    `413 payload_too_large` (Spezifikation S-11).
-   JSON decoding with `json.Decoder` and `DisallowUnknownFields()`.
-   Graceful shutdown via `server.Shutdown(ctx)` on SIGTERM.

The REST API is a management abstraction and should not pass all
internal DynSec commands through to the outside without filtering.

### 7.4 Example flow: create a client

1.  An authorized caller sends `POST /api/v1/clients`, usually
    without a password.
2.  The Security Service validates the username (naming rules),
    the provided password if applicable, and the requested role
    (managed roles with the `tf_` prefix only).
3.  If no password was provided, the service generates one. It sends
    `createClient` with the password and `textdescription: managed-by: pmss`
    to Mosquitto.
4.  After a successful response, it adds the role using `addClientRole`.
5.  It checks the result of both commands.
6.  The REST API responds with success or a meaningful
    error. A generated password appears once in the response.

Multiple DynSec commands in one request are not a transaction
(tested, Section 7.3).

> **Decision – compensation on partial success**
> If assigning a role or
> group fails during `POST /api/v1/clients`, the service deletes the newly created client
> (`deleteClient`) and reports the original error. If deletion also
> fails, this is explicitly stated in the response (client exists
> without a role) and in the audit log. A client without a role has no
> permissions due to default-deny.

If the response to `createClient` is lost due to a disconnection,
the client may still have been created (Section 7.2). The
service then reads it back according to A-9 instead of repeating `createClient`;
a retry would return `Client already exists`.

### 7.5 API authentication and authorization

The REST API is exposed through NPM with a public HTTPS endpoint.

> **Decision**
> The Security Service has **no web GUI**. The REST API therefore accepts
> **bearer tokens only** (`Authorization: Bearer
> <JWT>`), issued by the **configured OIDC provider**:
> the same provider where users sign in to TasmoFleet.
> **Keycloak** and **authentik** have been tested (Specification 2.3). There
> is no browser login, no sessions, and no local login.
> Only the OIDC provider as issuer is taken from the TasmoFleet pattern,
> not the browser login.

Advantages:

-   No redirect flow, session cookie, CSRF protection, or
    client secret for login to the service.
-   `curl`, scripts, and automated tests use the same flow.
-   Any future admin UI would be a separate application
    that authenticates with the OIDC provider itself and also calls the API
    with bearer tokens. This leaves the API unchanged.

Token verification in the service (`net/http` middleware before all handlers
except `/healthz`):

-   Signature against the provider's public keys (JWKS from
    `PMSS_OIDC_JWKS_URL`, otherwise `jwks_uri` from the discovery document
    of the issuer; keys are cached and reloaded for an unknown `kid`,
    at most once per minute).
-   `iss` must match the configured issuer **exactly** (fixed
    value, string comparison, T-8).
-   `aud` must contain the Security Service (Keycloak:
    audience mapper on the client scope; authentik: client ID of the
    Security Service provider).
-   `exp` with no tolerance, `nbf` with 5 minutes tolerance (as required by
    `go-oidc`); provider and broker host clocks are synchronized using NTP.
-   Only `RS256` and `ES256`; `none` and symmetric algorithms are
    rejected.
-   The token must have a `scope` claim (space-separated);
    without `scope` → `401 invalid_token` (Specification 2.1, T-9).
-   Token type is checked per provider (T-9): for Keycloak `typ` =
    `Bearer`, thereby rejecting ID and refresh tokens.
-   Missing or invalid token → `401`, missing scope → `403`.

> **Decision T-7 – JWT library**
> Token verification uses **`github.com/coreos/go-oidc/v3`** (tested
> with v3.21.0, internally `go-jose/v4`). ❌ No custom JWT implementation,
> ❌ no `lestrrat-go/jwx` or `golang-jwt/jwt` with `keyfunc`.
> - Verifier with **`oidc.NewVerifier(issuer, keySet, config)`**
>   (❌ not `oidc.NewProvider`): `issuer` = fixed issuer (T-8),
>   `keySet` = custom throttled `KeySet`, `config` with
>   `ClientID` = audience of the Security Service and
>   `SupportedSigningAlgs` = `RS256`, `ES256`.
> - Additionally in the service: `scope` claim required and scopes
>   extracted from it, token type per provider (T-9); `sub` and
>   `preferred_username` for audit, `azp` as additional information only
>   (for authentik, `azp` is the Security Service itself, not TasmoFleet).
> - JWKS through a custom `oidc.KeySet` that reloads at most once per minute
>   for an unknown `kid`. `oidc.RemoteKeySet` reloads for
>   every unknown `kid`; otherwise, every forged token would trigger a
>   request to the provider.
> - The JWKS address comes from `PMSS_OIDC_JWKS_URL`. If it is absent,
>   the `KeySet` reads `jwks_uri` from
>   `<Issuer>/.well-known/openid-configuration` on the first token and verifies that the
>   document's `issuer` exactly matches the configured issuer.
>   The discovery document is used only to find the JWKS address.

Why not `oidc.NewProvider`: `NewProvider` loads the
discovery document at startup, requiring a connection to the
provider, and checks that the issuer in the document matches the requested URL.
When accessed using the internal name (`keycloak:8080`), Keycloak returns the public
issuer because of `KC_HOSTNAME`, and `NewProvider` reports an
issuer mismatch. `NewVerifier` with a custom `KeySet` starts without
a connection to the provider and separates issuer from key retrieval; verification of
signature, `iss`, `aud`, `exp`/`nbf`, and algorithm is
the same as with `Provider.Verifier`.

> **Decision T-8 – fixed issuer, separate key retrieval**
> - The service compares `iss` with exactly one fixed issuer. How the
>   provider supplies a fixed issuer depends on the provider:
>   - **Keycloak:** The hostname is fixed (`KC_HOSTNAME` =
>     public URL). Without this setting, Keycloak uses the
>     request hostname in `iss`.
>   - **authentik:** authentik always builds the issuer from the
>     request hostname; there is no fixed setting
>     (tested with 2026.8.6). All callers (TasmoFleet, scripts,
>     `curl`) therefore obtain their tokens using the same public URL;
>     the reverse proxy forwards `Host` or `X-Forwarded-Host`.
>     The issuer is that of the Security Service provider, e.g.
>     `https://auth.example.org/application/o/pmss/`.
> - The source from which the service loads keys is configurable separately
>   from the issuer (`PMSS_OIDC_JWKS_URL`). This lets the service load
>   keys over the internal Docker network without going through NPM.
>   The issuer in the token remains the public name. If
>   `PMSS_OIDC_JWKS_URL` is absent, use `jwks_uri` from the issuer's
>   discovery document (T-7).

> **Decision T-9 – token type per provider**
> Derived from the authentik probe (`test/integration/authentik`,
> 24.11.2026):
> - Every token must have a `scope` claim, for every provider. Only
>   access tokens carry `scope`; a token without `scope` is rejected
>   with `401`.
> - Checking `typ` = `Bearer` is configurable
>   (`PMSS_OIDC_TYP_CHECK`): `bearer` (default, Keycloak) checks the
>   `typ` claim from Keycloak and thereby rejects ID and refresh tokens;
>   `none` (authentik) does not check `typ`. authentik does not set a
>   `typ` claim; both access and ID tokens have the `typ: JWT` header.
> - Without a `typ` check, audience and `scope` keep ID tokens out: a
>   TasmoFleet ID token has `aud` = TasmoFleet, and the Security Service's
>   provider does not issue ID tokens (no `openid` mapping).

> **Note: `go-oidc` v3.21.0 behavior (tested 21.11.2026)**
> Verified with `test/probes/jwt-go-oidc` against a local
> test issuer and the `pmss-test` test realm (Keycloak 26.8.2).
>
> | Case | Result |
> |---|---|
> | Access token with `aud` = Security Service and `account` | ✅ accepted; `aud` is checked as “contains” |
> | Incorrect `iss`, `aud` without Security Service, `aud` missing | ❌ rejected |
> | `exp` expired by 1 s | ❌ rejected – **no tolerance** for `exp` |
> | `nbf` 2 min or 10 min in the future | ✅ or ❌ – fixed 5 min tolerance, not configurable |
> | Different key with same `kid`, payload modified after signing | ❌ rejected |
> | `alg: none`, `HS256` using the public key as secret | ❌ rejected (algorithm list) |
> | `ES256` token with algorithm list `[RS256]` | ❌ rejected |
> | `azp` for any other client | ⚠️ accepted – `go-oidc` does not check `azp` |
> | Keycloak ID token (`typ: ID`) with matching `aud` | ⚠️ accepted by `go-oidc` alone; rejected by the `typ` check |
> | New key (rotation) | ✅ accepted on first token with new `kid` |
> | 10 tokens with unknown `kid` | ⚠️ `RemoteKeySet` loads JWKS **10 times**; throttled KeySet at most once per minute |
> | Keycloak: `msm-test-rw` / `msm-test-ro` | ✅ `read write` or `read` only |
> | Keycloak: exchanged token for `alice` / `bob` | ✅ username in token; `write` only for `alice` |
> | Keycloak: original TasmoFleet token, ID token | ❌ rejected (`aud` does not include Security Service) |
> | Keycloak: refresh token | ❌ rejected (signed with `HS512`, not in algorithm list) |

Permissions via scopes:

| Scope | Permitted |
|---|---|
| `read` | All `GET` endpoints |
| `write` | All modifying endpoints (`POST`, `PUT`, `PATCH`, `DELETE`); does not automatically include `read` |

> **Decision – authorization and tokens (Overview questions 14, 21, 22)**
> - **Scopes only in the service:** The service checks `read`/`write`, not
>   roles or groups. The OIDC provider issues `write` only to users
>   with the `security-admin` role or group (Keycloak and
>   authentik below). The provider thereby enforces D-22, and the
>   service remains independent of TasmoFleet roles.
> - **TasmoFleet via Token Exchange:** TasmoFleet exchanges the
>   signed-in user's token with the same provider using Token Exchange (RFC 8693)
>   for a token with `aud` = Security Service and the
>   required scopes. `sub` remains the user, and the audit identifies the
>   person who initiated a change. How TasmoFleet requests `write`
>   is specified in the specification (S-16, S-17).
> - **Second factor only in the provider:** A conditional login flow
>   requires a second factor for `security-admin`. The service
>   does not check `acr`/`amr`.
> - **No service accounts with `write` in production:** They would
>   have no second factor. Administrators use the Device
>   Authorization Grant via `curl` (browser login with second factor).
>   Client Credentials with `write` are available only in test environments.
> - **No audit endpoint:** The service audit remains in the log
>   (phylax-syslog-service, access for operations only). TasmoFleet
>   maintains its own audit of approvals; `admin` may read it.

Token sources:

| Caller | Flow | Scopes | Remark |
|---|---|---|---|
| TasmoFleet on behalf of a user | Token Exchange (RFC 8693) | `read`, `write` only for `security-admin` | TasmoFleet is a confidential client; `aud` of exchanged token is only the Security Service |
| Administrator via `curl` | Device Authorization Grant | `read`, `write` only for `security-admin` | Browser login with second factor; username is in the token |
| Scripts, monitoring, drift check | Client Credentials (service account) | `read` only | Separate client or service account for each caller |
| Automated tests | Client Credentials | `read`, `write` | `msm-test-rw`, `msm-test-ro` (Section 7.9) |

**Keycloak** (via Keycloak configuration as code):

-   Fixed hostname (`KC_HOSTNAME` = public URL), so that the issuer
    does not depend on the access path (T-8).
-   Client scopes `read` and `write` with an audience mapper for the
    Security Service; `write` mapped to the `security-admin` role.
    If the role is missing, Token Exchange responds with `200` and
    `scope=read`.
-   TasmoFleet client: confidential, “Standard Token Exchange” enabled
    (Keycloak 26.2 or later), `read`/`write` as optional client scopes.
-   Client for `curl` with Device Authorization Grant, without a
    service account.
-   Conditional login flow with OTP or WebAuthn for `security-admin`,
    including for the Device Authorization Grant.
-   `PMSS_OIDC_TYP_CHECK=bearer` (Standard).

**authentik** (via blueprints):

-   Minimum version 2026.8.3: Token Exchange is available starting with 2026.8.0 and
    must be enabled for the provider under “Grant Types”; 2026.8.3
    fixes exchange without a signing key. Tested with 2026.8.6.
-   Dedicated OAuth2 provider with its own application for the Security
    Service, client ID = Security Service audience; its own
    signing key pair (RS256). The issuer is that of the provider.
-   Scope mappings `read` (provides `preferred_username` for the audit)
    and `write` on the Security Service provider; no `openid` mapping.
-   The Security Service provider trusts the TasmoFleet provider
    (“Federated OAuth2/OpenID Providers”); only then is Token
    Exchange from TasmoFleet allowed. The “Token exchange” grant
    (Impersonation) is enabled on the TasmoFleet provider.
-   `write` only for `security-admin`: an expression policy on the
    Security Service application rejects a request with `write` for
    users outside the group (context `oauth_scopes`).
    Unlike Keycloak, the entire request then fails
    (`400 invalid_grant`); TasmoFleet therefore requests it according to S-16.
-   All callers obtain tokens using the same public URL (T-8).
-   Second factor: authenticator validation in the login flow for
    `security-admin`. It remains an open issue whether app passwords provide a path to `write`
    without a second factor (Section 7.9, F-7).
-   `PMSS_OIDC_TYP_CHECK=none` (T-9).

Example (read script with service account, Keycloak):

``` bash
TOKEN=$(curl -s -d grant_type=client_credentials \
  -d client_id=msm-reader -d client_secret=... \
  https://<keycloak>/realms/<realm>/protocol/openid-connect/token \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" https://<msm>/api/v1/export
```

For authentik, the token endpoint is
`https://<authentik>/application/o/token/`; service accounts authenticate
with `grant_type=client_credentials`, the `client_id` of the Security Service
provider, `username`, and an app password.

Beispiel (Token Exchange in TasmoFleet, konzeptionell, Keycloak):

``` bash
curl -s -u tasmofleet:<client-secret> \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token=<access-token-des-benutzers> \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=<client-id-des-security-service> \
  -d scope="read write" \
  https://<keycloak>/realms/<realm>/protocol/openid-connect/token
```

For authentik, use the same request with the authentik token endpoint and
`audience` = Client-ID des Providers des Security Service
(Spezifikation 2.2).

Service configuration via environment variables: issuer (fixed
value, T-8), optional JWKS URL (`PMSS_OIDC_JWKS_URL`, otherwise via
discovery), expected audience, scope names, and token type
check (`PMSS_OIDC_TYP_CHECK`, T-9). The service needs no
client secret because it only verifies tokens.

In production, key retrieval can use the internal network. For this,
the service needs a shared Docker network with the provider
(Section 4.2), and `PMSS_OIDC_JWKS_URL` points to the provider's internal name.
The issuer remains the public URL.

For each action, the audit log contains the caller from the token (`sub` and
`preferred_username`, `azp` as additional information), never the token
itself.

TLS alone does not authenticate a user or replace
API authorization. Verification is performed as `net/http` middleware before the
handlers.

The internal proxy hop from NPM to the Go service can initially use HTTP within a
protected Docker network. If end-to-end TLS encryption to the Go process is required,
this hop must also be secured separately with TLS
(`server.ListenAndServeTLS` mit `crypto/tls`).

The service itself receives only the permissions required for its task
(`role_security_manager`). The admin certificate
`pmss-admin` and its key are not given to browsers, devices, or
other applications.

**Break-glass (D-24):** emergency access without the Security Service and without
the OIDC provider, using the separate identity `pmss-breakglass-admin`. A
one-off container on the internal network; the key is mounted only for the
duration of the operation:

``` bash
docker run --rm --network <mqtt-internal> \
  -v ~/internal-ca/breakglass:/bg:ro \
  -v ~/internal-ca/server-ca/ca.crt:/ca.crt:ro \
  eclipse-mosquitto:2.1.2 \
  mosquitto_ctrl -h mosquitto -p 8884 --cafile /ca.crt \
    --cert /bg/pmss-breakglass-admin.crt --key /bg/pmss-breakglass-admin.key \
    dynsec listClients
```

Every login by `pmss-breakglass-admin` is visible in the broker log
(username `pmss-breakglass-admin`) and is monitored.

### 7.6 Logging

Logging uses `log/slog`:

-   JSON handler (`slog.NewJSONHandler`) on stdout, so Docker can collect
    the logs.
-   Log level configurable via configuration or environment variable.
-   Audit events (who, what, when, result) as separate log entries
    with a fixed attribute, e.g. `"log_type":"audit"`.
-   Before each change, the service reads the affected object and
    writes the **before and after state** to the audit event.
    Passwords and password hashes are never included; a
    password change appears only as an event.
-   There is no audit endpoint. The
    audit entries are sent with the other logs to the
    phylax-syslog-service; operations-only access.
-   Passwords, tokens, and key material are never logged. Types
    with sensitive fields implement `slog.LogValuer` and return
    masked values.

### 7.7 Container and build

> **Decision**
> The runtime base is **Debian Slim**, not `scratch`. Image size is
> not a decision criterion.

Rationale:

-   System certificates (`ca-certificates`) are available for any
    outbound connections, e.g. JWKS retrieval from the
    OIDC provider via the public URL.
-   Time zone data (`tzdata`) is available for readable log timestamps and
    time-dependent logic.
-   A shell and basic tools make debugging in the container easier
    (`docker exec`).

Build approach:

-   Multi-stage build: `golang:1.27-trixie` as the build stage,
    `debian:trixie-slim` (Debian 13) as the runtime stage.
-   The current Go version is used (currently 1.27).
    The `1.27-trixie` tag receives patch releases automatically; a
    move to the next major version (1.28) is made deliberately by
    changing the Dockerfile and `go.mod`.
-   `CGO_ENABLED=0`, multi-architecture build for `linux/amd64` and
    `linux/arm64` (`docker buildx`).
-   **Required:** explicitly install `ca-certificates` and `tzdata` in the
    runtime stage using `apt-get install --no-install-recommends`,
    because they are not reliably present in the Slim image.
    Without these packages, Debian Slim's advantages over
    `scratch` (system certificates, time zone data) are lost.
-   Run as a non-root user with a fixed UID/GID, matching
    the file permissions of the mounted certificates.

Conceptual Dockerfile:

``` dockerfile
FROM golang:1.27-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" \
    -o /out/phylax-mqtt-security-service ./cmd/phylax-mqtt-security-service

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 msm && useradd -u 10001 -g msm -M -s /usr/sbin/nologin msm
COPY --from=build /out/phylax-mqtt-security-service /usr/local/bin/
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/phylax-mqtt-security-service"]
```

Conceptual Compose configuration: CA certificates and
admin certificate mounted read-only, no password secret.

``` yaml
services:
  phylax-mqtt-security-service:
    image: ghcr.io/noschvie/phylax-mqtt-security-service:<tag>
    read_only: true
    environment:
      - TZ=<zeitzone>
    volumes:
      - ./volumes/mqtt-server-ca/ca.crt:/run/mqtt-server-ca/ca.crt:ro
      - ./volumes/phylax-mqtt-security-service/certs:/run/secrets/mqtt-client:ro
    networks:
      - mqtt-internal
      - api-internal

  mosquitto:
    volumes:
      - ./volumes/mqtt-admin-ca/ca.crt:/mosquitto/admin-ca/ca.crt:ro
      - ./volumes/mosquitto/certs:/mosquitto/certs:ro
```

The root filesystem can be mounted read-only using `read_only: true`,
since the service writes no local state.

### 7.8 Build and release process

> **Decision**
> Local builds are for testing only. Production images are built via
> a **GitHub Actions workflow** and pushed to the GitHub Container
> Registry (`ghcr.io`). The broker host runs only the image from
> the registry (`docker compose pull`).

-   **Local:** `go test -race ./...`, `go vet ./...`, and
    `docker build` for experimentation. Locally built images are not
    used in production.
-   **GitHub Actions:** Workflow with `docker buildx` for `linux/amd64`
    and `linux/arm64`. Unit and integration tests (Section 7.9)
    run before the build; the image is pushed to
    `ghcr.io/noschvie/phylax-mqtt-security-service`.
-   **Tags:** Version tags (`vX.Y.Z`) produce release images with the same
    tag; builds from the main branch optionally use `edge`.
-   **Rebuilds:** Regular rebuilds (e.g. scheduled in the workflow),
    so Go patch releases and Debian security updates are included in the image.

### 7.9 Test strategy

> **Decision**
> There are two test levels: **unit tests** with a test issuer in
> Go, and **integration tests** with a **Keycloak dev container**
> configured through a realm JSON,
> together with a real Mosquitto. For **authentik**, there is a
> separate **probe** using a blueprint; it checks what authentik writes to
> tokens and does not yet run in CI. Keycloak and authentik
> have separate test environments and test cases.

| Test level | Token issuer | Scope | Runs |
|---|---|---|---|
| Unit tests (`go test -race ./...`) | `httptest` test issuer with its own test keys | Token verification including error cases, handlers, validation, correlation, DynSec JSON | locally and in every workflow run |
| Integration tests | Keycloak dev container with realm JSON | Full path: token from Keycloak → REST → MQTT/mTLS → DynSec | locally via Compose and in workflow `integration.yml` before image build |
| authentik probe | authentik with blueprint | Tokens from authentik: scopes, audience, Token Exchange, issuer | locally via Compose (`test/integration/authentik`), not yet in CI |
| Second factor | Keycloak or authentik | Browser and device code login, followed by Token Exchange | manually, one guide per provider (`SECOND-FACTOR.md`) |

**Unit tests:** The test issuer is an `httptest` server that serves a
JWKS and signs tokens with test keys. This makes it possible to
quickly test error cases without containers:

-   [ ] expired token, `nbf` in the future
-   [ ] invalid signature, unknown `kid`, algorithm `none`
-   [ ] incorrect `iss` (also same realm, different hostname), missing
    or incorrect `aud`
-   [ ] missing scope (`read` instead of `write`) → `403`
-   [ ] missing or malformed `Authorization` header → `401`
-   [ ] token without `scope` claim → `401`
-   [ ] with `PMSS_OIDC_TYP_CHECK=bearer`: `typ` other than `Bearer` (ID
    or refresh token) → `401`; with `none`: token without `typ` and with
    `scope` accepted
-   [ ] Many tokens with unknown `kid` trigger at most one
    JWKS fetch per minute
-   [ ] With `PMSS_OIDC_JWKS_URL`, use that address without a
    discovery request; otherwise `jwks_uri` is taken from the
    discovery document, and a mismatched `issuer` in the document causes
    rejection

**Integration tests (Keycloak):** A Compose file under
`test/integration/` starts:

-   Keycloak **26.8.2** (same version as production) with
    `start-dev --import-realm`; the test realm JSON is located under
    `/opt/keycloak/data/import`. `KC_HOSTNAME` sets the issuer:
    tokens obtained from the host or from the Compose network (`keycloak:8080`)
    have the same `iss`. The service loads the
    keys from `keycloak:8080` via `PMSS_OIDC_JWKS_URL` (T-8).
-   Mosquitto **2.1.2** with DynSec, listener 8884 with
    `use_identity_as_username` and test Admin CA, pre-initialized
    `dynamic-security.json` as after bootstrap in Section 6.2:
    `pmss-admin` without a password and with `role_security_manager`, and the
    existing user `legacy-shared-user` with `role_legacy`.
-   Test server CA, test Admin CA, and certificates are generated by
    script for each test run and are not checked into the repository (template:
    `mqtt-acl-verify/testbroker-dynsec/make-certs.sh`).

The test realm JSON contains:

-   Client scopes `read` and `write` with an audience mapper.
-   Client `msm-test-rw` with service account, scopes `read` and
    `write`, and the `security-admin` role. Without the role, even
    a service account receives no `write` (role mapping on the client scope).
-   Client `msm-test-ro` with service account and `read` only (for
    negative tests).
-   `security-admin` role, `write` client scope mapped to
    this role.
-   Client `msm-test-rw-norole` with service account and scopes
    `read` and `write`, but without `security-admin` (negative test for
    role mapping).
-   Test users with and without `security-admin`, and a confidential
    client `tasmofleet-test` with Standard Token Exchange enabled.
-   A dedicated client scope `basic` with mappers for `sub` and
    `preferred_username`: if the realm JSON contains a custom
    `clientScopes` list, Keycloak does not create its built-in scopes,
    and `preferred_username` would otherwise be absent from the token. The service
    audit needs the username.
-   Login flow with second factor (OTP) for `security-admin`, a
    `pmss-cli` client for the Device Authorization Grant, and a
    `pmss-api-tester` client (`read` only) for the manual test of the
    second factor (`test/integration/keycloak/SECOND-FACTOR.md`).
-   Fixed test secrets. This is safe because the realm exists only in tests.
    Where possible, it is derived from the existing
    Keycloak configuration as code so test and production
    configurations do not diverge.

Notes for GitHub Actions:

-   `services:` in GitHub Actions does not allow a custom startup command,
    so the environment is started in a workflow step using
    `docker compose up -d`. The same Compose file is used locally.
-   Start Keycloak with `KC_HEALTH_ENABLED=true`; the workflow waits
    for `/health/ready` on management port 9000 before the tests
    start.
-   After the tests, run `docker compose down -v`; save container logs
    as an artifact on failure.

Integration test cases (excerpt; all paths under `/api/v1/`):

-   [ ] Obtain a token from `msm-test-rw`, create a client, assign a role,
    read the client, and delete it.
-   [ ] Token from `msm-test-ro`: `GET` allowed, `POST` → `403`.
-   [ ] Token Exchange via `tasmofleet-test` for a user with
    `security-admin`: exchanged token with `aud` = Security Service,
    scope `write`, `sub` = user; modification allowed, audit shows the
    user.
-   [ ] Same for a user without `security-admin`: exchanged
    token without `write` scope, modification → `403` (tests
    role mapping on the client scope with Keycloak 26.8.2).
-   [ ] Original TasmoFleet token without `aud` = Security Service →
    `401`.
-   [ ] Exchange another client's token: `tasmofleet-test` exchanges
    a token issued for `msm-test-rw` → Keycloak rejects it
    (`403 Client is not within the token audience`). TasmoFleet can
    exchange only tokens issued for TasmoFleet.
-   [ ] Tokens obtained from the host and from the Compose network (`keycloak:8080`)
    have the same `iss` and are accepted by the service.

> **Keycloak test results (Keycloak 26.8.2, 10 of 10 passed)**
> The Keycloak part of the test cases above is implemented in the repository under
> `test/integration/keycloak` (`check_tokens.py`, realm
> `pmss-test`, CI workflow `integration.yml`). It checks what
> Keycloak writes into the tokens; the Security Service is not yet
> involved.
>
> | Check | Result |
> |---|---|
> | `msm-test-rw` (with `security-admin`) | ✅ `read write`, `aud` = Security Service |
> | Service account with `write`, without `security-admin` | ✅ no `write` |
> | Token Exchange for user with `security-admin` | ✅ `aud` is Security Service only, `read write`, `sub` and `preferred_username` = user |
> | Token Exchange for user without `security-admin` | ✅ no `write` |
> | Original TasmoFleet token | ✅ `aud` without Security Service |
> | Exchange a token from another client | ✅ `403 Client is not within the token audience` |
>
> **Important for TasmoFleet:** If `write` is missing, Keycloak does not
> treat this as an error. Token Exchange for a user without `security-admin`
> responds with `200` and `scope=read`. TasmoFleet must check the `scope` of the
> exchanged token instead of relying on an error
> (Specification S-16).

**authentik probe:** `test/integration/authentik` starts authentik
**2026.8.6** with PostgreSQL 18 and applies the blueprint
`blueprints/pmss-test.yaml`. It is the counterpart to the realm JSON:

-   Provider `pmss` (client ID = audience of the Security Service) with
    scope mappings `read` and `write`, trust for `tasmofleet-test`
    and an expression policy allowing `write` only for the
    `security-admin` group.
-   Provider `tasmofleet-test` with Token Exchange, and another provider
    `other-app` for negative tests.
-   Group `security-admin`, users `alice` (in group) and `bob`,
    service accounts `msm-test-rw`, `msm-test-ro`, `msm-test-rw-norole`
    with app passwords; a separate signing key pair for each test run.

`check_tokens.py` checks the same cases as for Keycloak and records in
`INFO` lines where authentik behaves differently.

> **authentik probe results (authentik 2026.8.6, 16 of 16 passed, 24.11.2026)**
>
> | Check | Result |
> |---|---|
> | Signature, issuer | ✅ `RS256`, `kid` in the JWKS of provider `pmss`, `iss` = Discovery |
> | `msm-test-rw`, `msm-test-ro` | ✅ `read write` or `read` only, `aud` = Security Service |
> | `write` without `security-admin` (service account, Token Exchange) | ✅ no `write` – ⚠️ the entire request is rejected (`400 invalid_grant`) |
> | Token Exchange for user with `security-admin` | ✅ `aud` is Security Service only, `read write`, `sub` and `preferred_username` = user |
> | Token Exchange with `read` only for user without `security-admin` | ✅ `read` |
> | Original TasmoFleet token | ✅ `aud` without Security Service |
> | Exchange to a provider without trust for TasmoFleet | ✅ rejected (`invalid_target`) |
> | Exchange a token from the Security Service or `other-app` | ✅ rejected (`invalid_grant`) |
>
> Differences from Keycloak (consequences in T-8, T-9, S-16):
> - no `typ` claim; header `typ: JWT` on access and ID tokens;
> - `azp` in the exchanged token is the Security Service, not
>   TasmoFleet; no `act` (impersonation);
> - `iss` follows the request hostname (`Host: authentik-server:9000`
>   produces a different issuer);
> - `scope` is a space-separated string as with Keycloak.

**Second factor:** For each provider, a guide describes the
manual test of SEC-36 (`test/integration/keycloak/SECOND-FACTOR.md`,
`test/integration/authentik/SECOND-FACTOR.md`): browser
and Device Code login with a second factor, followed by Token Exchange, and
confirmation that no path without a second factor yields a token with `write`.
The paths without browser login are critical: the Keycloak test client's
Password Grant, and the authentik app password. The authentik
test (F-7) is deferred until an authentik instance is
available for testing.

Additional integration test cases:

-   [ ] No token → `401`.
-   [ ] A created MQTT client can authenticate to the broker and publish
    or subscribe according to its role.
-   [ ] Service without a valid client certificate cannot reach port 8884.
-   [ ] Service using a server CA certificate instead of an Admin CA certificate
    is rejected on port 8884.
-   [ ] `POST /api/v1/clients` with a `pmss-…` name, with `=`/`,` and
    a password, and `POST …/password` for a `CN=` client are rejected.
-   [ ] Modifying requests for `legacy-shared-user` and `role_legacy`
    are rejected with `403`; likewise `POST /api/v1/roles` without the `tf_`
    prefix.
-   [ ] Client created without a password: response contains a password
    of 24 characters `A–Z a–z 0–9`, and it can authenticate to the broker.
-   [ ] Provided password containing `;`, a space, or a different length
    is rejected with `422`.
-   [ ] No password appears in logs or audit entries.
-   [ ] ACL without `allow` or with an unknown `acltype` is rejected with `422`
    before a command is sent to the broker.
-   [ ] `PUT /api/v1/roles/{role}/acls` fully replaces the list;
    the read-back state matches the submitted list.
-   [ ] Modification with stale `If-Match` → `412`, without `If-Match` →
    `428`; object remains unchanged.
-   [ ] Modification via `mosquitto_ctrl` between `GET` and `PUT` is
    detected (`412`).
-   [ ] `POST /api/v1/clients` with a nonexistent role: client
    is deleted again; error appears in response and audit log.
-   [ ] Audit entry for a change contains before and after state,
    but no password hash.
-   [ ] `GET /api/v1/export` includes all managed objects and no
    unmanaged ones (neither `legacy-shared-user` nor
    `role_legacy` in the test).
-   [ ] A deny rule without higher priority than an allow rule of the same
    type produces a warning.

Broker connection test cases (A-9, Section 7.2):

-   [ ] Broker disconnect: after reconnect, the response topic is
    resubscribed and requests receive responses.
-   [ ] Disconnect after a modifying command has reached the broker (response lost):
    the service reads back the state, the REST response matches the actual state,
    and the command is not repeated.
-   [ ] Request without a broker connection: `broker_unavailable`; the
    command is not sent after reconnect.
-   [ ] Concurrent `mosquitto_ctrl` requests on the response topic:
    foreign responses are discarded and do not interfere with in-flight requests.

Interface specification test cases:

-   [ ] `GET /api/v1/info` with `read` returns `apiVersion` `1.x`,
    prefixes and marker from the configuration, and
    `limits.maxRequestBytes` ≥ 1048576; without a token, `401`.
-   [ ] Every error has `Content-Type: application/problem+json`,
    `status` equal to the HTTP status, and a `code` from the
    specification's list.
-   [ ] `422` contains `errors` with a valid JSON Pointer.
-   [ ] `401` and `403 insufficient_scope` set `WWW-Authenticate`.
-   [ ] Export: lists and ACLs are sorted; two exports of the same
    state are byte-identical (except for `exportedAt`).
-   [ ] Export: client with `CN=…` has `authType: certificate`.
-   [ ] Add client to group: group ETag changes, client ETag does not.
-   [ ] Assign role to client: `200` with client in body and new
    `ETag`; revoke: `204`, ETag returns to previous value.
-   [ ] Password change: client ETag remains unchanged.
-   [x] `getClient` returns no password hash (basis for S-5) –
    ✅ confirmed at the broker (21.11.2026, `mqtt-acl-verify`,
    `tests/test_dynsec_control.py`).
-   [ ] Disable and then enable a client: ETag afterwards matches
    the previous one (missing `disabled` treated as `false`).
-   [ ] `POST /api/v1/roles` with valid ACLs: role fully created,
    read-back matches submitted data.
-   [ ] `POST /api/v1/roles` with invalid ACL: `422`, no role
    created.
-   [ ] `POST /api/v1/clients/{username}/password` for a `CN=` client:
    `409 certificate_client`; `POST /api/v1/clients` for a `CN=` client
    with a password: `422`.
-   [ ] `POST /api/v1/clients/{username}/disable` and `…/enable` for
    a `CN=` client: `409 certificate_client`, no command sent to the
    broker; successful for a password client (A-10).
-   [ ] Request body exceeding `limits.maxRequestBytes`:
    `413 payload_too_large`.
-   [ ] Path parameter `CN%3Dhomeassistant%2CO%3Dmqtt-apps` is correctly
    decoded.
-   [ ] Old path `/api/export` (without version): `404`.

The broker-side cases are checked by `mqtt-acl-verify`
(`testbroker-dynsec/cases-mtls.yaml`): admin authentication cases `p-*`
(listener 8886 in the test broker = 8884 in production), TLS and application
cases `t-*` and `app-*` (8883 = 8883, 8887 = 8885). Control API behavior
(`correlationData`, `getClient`) is checked by
`tests/test_dynsec_control.py`; `autopaho` behavior on reconnect and pending requests by
`probes/autopaho-reconnect/` (Section 7.2).

## 8. Security requirements

| ID | Requirement |
|---|---|
| SEC-01 | Port 8884 is not published on the Docker host. |
| SEC-02 | Port 8884 is reachable only over the dedicated internal Docker network. |
| SEC-03 | The connection on port 8884 uses TLS and mandatory client certificates from the Admin CA. |
| SEC-04 | The service verifies the CA chain (server CA) and hostname/SAN of the broker certificate (`crypto/tls`, its own `RootCAs` pool, no `InsecureSkipVerify`). |
| SEC-05 | The private key of the admin certificate is kept only server-side, mounted read-only, and never written to logs. |
| SEC-06 | REST access is available exclusively over HTTPS. |
| SEC-07 | The REST API checks authentication and permissions; NPM TLS alone is not sufficient. |
| SEC-08 | CA private keys and private service keys are not stored in Git. |
| SEC-09 | `dynamic-security.json` and backups are protected against unauthorized access. |
| SEC-10 | Admin actions are logged traceably (`log/slog`), without logging passwords or tokens. |
| SEC-11 | DynSec admins receive only the required Control API permissions (`role_security_manager`). |
| SEC-12 | MQTT device access and internal management access are separated logically and at the network level. |
| SEC-13 | CA certificates are mounted separately and read-only and are not added to the container's system trust store. CA private keys are not mounted into any container. |
| SEC-14 | The Security Service container runs as a non-root user; certificates are mounted read-only. |
| SEC-15 | The REST API accepts only bearer tokens from the configured OIDC provider; signature, `iss` (fixed value, exact comparison), `aud`, `exp`, algorithm, and `scope` claim are checked, plus `typ` (`Bearer`, T-9) for Keycloak. There is no browser, session, or local login. |
| SEC-16 | Modifying endpoints require scope `write`, read endpoints scope `read`. The OIDC provider issues `write` only to users with the `security-admin` role or group. |
| SEC-17 | DynSec admins (`pmss-admin`, `pmss-breakglass-admin`, and their numbered successors) have no password; they authenticate on listener 8884 only using an Admin CA certificate. The broker rejects them on all other listeners. |
| SEC-18 | The Admin CA issues certificates only for admin identities. After bootstrap, neither a DynSec admin with a password nor the `admin` role exists. |
| SEC-19 | `role_security_manager` has access only to `$CONTROL/dynamic-security/#` and `$SYS/#`, with no access to application topics. |
| SEC-20 | Admin certificates are disabled using `deleteClient` (or by revoking roles), not `disableClient`. The REST API rejects `enable`/`disable` for certificate clients (A-10). |
| SEC-21 | TLS listeners 8883 and 8885 accept TLS 1.2 or higher (`tls_version tlsv1.2`). |
| SEC-22 | Listener 8885 accepts only certificates from the App CA and uses the subject as the username (`use_subject_as_username`). No listener using client certificates trusts more than one client CA. |
| SEC-23 | The App CA issues only subjects `/O=mqtt-apps/CN=<name>`. Certificate clients have no password; password clients have neither `=` nor `,` in their names; `pmss-*` and `role_security_manager` are reserved. The subject of a certificate disabled due to compromise is not reused. |
| SEC-24 | Reachability: 1883 only from the IoT network, 8883 and 8885 from the LAN (8883 also from the IoT network if needed), 8884 from no network (router firewall). |
| SEC-25 | The legacy role `role_legacy` permits only application topics (`#`), with no access to `$SYS/#` or `$CONTROL/#`. |
| SEC-26 | Debug logging for the topic inventory is limited to one week; log files contain no payloads or passwords and are protected against unauthorized access. |
| SEC-27 | The Security Service modifies only managed objects: clients marked `managed-by: pmss` in `textdescription`, and roles and groups with the `tf_` prefix. |
| SEC-28 | MQTT passwords consist of exactly 24 characters `A–Z a–z 0–9`; generated passwords come from `crypto/rand`, appear once in the response, and are neither stored nor logged. |
| SEC-29 | Names of disabled admins and app clients are not reused; successors receive a sequential number. |
| SEC-30 | The Security Service validates every ACL itself (`acltype` from the fixed list, `allow` required) and checks the read-back state after `modifyRole`. |
| SEC-31 | Modifying requests for existing objects require `If-Match`; if the state differs, nothing is changed (`412`). |
| SEC-32 | Audit events contain before and after state, never passwords or password hashes. |
| SEC-33 | The host backs up `dynamic-security.json` regularly, independently of TasmoFleet and the Security Service. |
| SEC-34 | TasmoFleet calls the service only with user tokens exchanged via Token Exchange (`aud` = Security Service, `sub` = user), not with its own service account with `write`. |
| SEC-35 | No service account has the `write` scope in production. |
| SEC-36 | The second factor for `security-admin` is enforced by the OIDC provider for every login path leading to a token with scope `write` (browser, Device Authorization Grant, then Token Exchange). |
| SEC-37 | Error responses (`detail`, `errors`) and warnings never contain passwords, password hashes, or tokens. |
| SEC-38 | Request bodies are limited to `limits.maxRequestBytes` (at least 1 MiB); larger bodies are rejected with `413` without processing. |
| SEC-39 | If JWKS retrieval uses the internal network (`PMSS_OIDC_JWKS_URL`), the shared network with the OIDC provider is restricted to the required containers. |
| SEC-40 | If the provider builds the issuer from the request hostname (authentik), all callers obtain tokens through the same public URL, and the reverse proxy forwards `Host` or `X-Forwarded-Host` unchanged. |

## 9. Migration plan

The migration is performed in a controlled manner with a rollback option.

> **Decision**
> The internal listener 8884 is configured before
> DynSec is enabled. From activation onward, all
> management is performed over 8884 with a certificate; an admin can never
> authenticate over 1883.

| Phase | Contents |
|---|---|
| Phase 0 | Preparation |
| Phase 1 | Internal CAs and listener 8884 |
| Phase 2 | Prepare DynSec (offline bootstrap) |
| Phase 3 | Enable DynSec |
| Phase 4 | Functional test |
| Observation | Topic inventory, one week, in parallel with Phases 5 and 6 |
| Phase 5 | TLS listeners 8883 and 8885 |
| Phase 6 | Go Security Service |
| Phase 7 | Refine permissions |

### Phase 0 – Preparation

-   [ ] Check the Compose file and actual mounts.
-   [ ] Create a complete backup of the Mosquitto configuration, password file,
    and data directory.
-   [ ] Restrict access to the backup.
-   [ ] Document current MQTT clients and critical topics.
-   [ ] Check the hash format in `pwfile`: `$7$`.
-   [ ] Identify applications subscribing to `$SYS/#` (e.g. monitoring,
    MQTT viewer); they will lose this access with `role_legacy`.
-   [ ] Document the rollback path: restore the backed-up `mosquitto.conf`
    and restart; `pwfile` remains unchanged.

### Phase 1 – Internal CAs and listener 8884

-   [ ] Create the server CA and Admin CA; back up CA keys offline.
-   [ ] Issue a server certificate (server CA, SAN `mosquitto`).
-   [ ] Issue admin certificates `pmss-admin` and `pmss-breakglass-admin`
    (Admin CA); store `pmss-breakglass-admin` offline.
-   [ ] Mount the Admin CA certificate separately and read-only in Mosquitto.
-   [ ] Configure listener 8884 with `require_certificate true` and
    `use_identity_as_username true` (Section 6.3).
-   [ ] Do not publish port 8884.
-   [ ] Check the configuration with `mosquitto --test-config`; restart.
-   [ ] Check the TLS handshake with the admin certificate; it must fail
    without a certificate and with a server CA or foreign CA certificate.
    Until DynSec is enabled, the listener has no
    other function.

### Phase 2 – Prepare DynSec

-   [ ] Perform the offline bootstrap according to Section 6.2:
    initialize `dynamic-security.json`, set default-deny,
    create `role_security_manager`, and create `pmss-admin` and
    `pmss-breakglass-admin` without passwords.
-   [ ] Create the legacy role `role_legacy` (Section 6.5).
-   [ ] Create client `legacy-shared-user` without a password and
    assign `role_legacy`.
-   [ ] Delete role `admin` and bootstrap admin `dynsec-bootstrap`.
-   [ ] Stop the temporary broker and import the password hash of
    `legacy-shared-user` using `import-pwfile.py`
    (Section 6.2, step 5).
-   [ ] Check the result in `dynamic-security.json`: no admins with
    passwords, no `admin` role, `legacy-shared-user` with
    `encoded_password`.

### Phase 3 – Enable DynSec

-   [ ] Add the plugin configuration (Section 6.3).
-   [ ] Disable `password_file` in `mosquitto.conf`; leave the
    `pwfile` itself in place (rollback path).
-   [ ] Keep `acl_file` disabled or remove it.
-   [ ] Keep `allow_anonymous false`.
-   [ ] Validate the Mosquitto configuration before restarting.
-   [ ] Add the `syslog` logging driver for Mosquitto (Section 6.6).
-   [ ] Perform the planned restart (`docker compose up -d`).

A broker restart is required to enable the plugin for the first time and for
listener/TLS configuration changes. Subsequent
client, group, role, and ACL changes do not require a broker restart.

### Phase 4 – Functional test

-   [ ] All devices and applications connect using their existing
    credentials, with no changes on the devices.
-   [ ] Check applications that used `$SYS/#`.
-   [ ] `legacy-shared-user` has no access to `$SYS/#` or
    `$CONTROL/#`.
-   [ ] Mosquitto logs arrive at the phylax-syslog-service.
-   [ ] Test publishing and subscribing on the topics used so far.
-   [ ] Account for retained messages and existing sessions.
-   [ ] Test DynSec changes over 8884 using `pmss-breakglass-admin`
    (`mosquitto_ctrl`, Section 7.5); check the output, not only
    the exit code.
-   [ ] Admin usernames are rejected on 1883.
-   [ ] Check that changes to `dynamic-security.json` persist
    and survive a broker restart.

### Observation – topic inventory (one week, after Phase 4)

-   [ ] Set `log_type all` and send SIGHUP (Section 6.6);
    note the start time.
-   [ ] After one week, restore the normal `log_type` lines
    and send SIGHUP.
-   [ ] Create and store the inventory using `mqtt-acl-verify inventory`
    on the phylax-syslog-service files.

Observation runs in parallel with Phases 5 and 6; its results are the
basis for Phase 7.

### Phase 5 – TLS listeners 8883 and 8885

-   [ ] Issue the external server certificate (server CA, RSA, SAN
    `mqtt.example.org`, 12 months).
-   [ ] Create DNS entry `mqtt.example.org` in the local DNS and
    verify resolution on the clients.
-   [ ] Create the App CA; back up its key offline.
-   [ ] Mount the App CA certificate separately and read-only in Mosquitto.
-   [ ] Configure listeners 8883 and 8885 (Section 6.3),
    run `mosquitto --test-config`, and restart.
-   [ ] Publish ports 8883 and 8885; add router firewall rules
    according to Section 4.1 (outside this project).
-   [ ] Check: TLS 1.1 rejected on 8883/8885; Admin CA and
    server CA certificates rejected on 8885; App certificate rejected on 8884.
-   [ ] Connect the first application using an App certificate (client
    `CN=<name>,O=mqtt-apps` without a password, assign a role) and verify
    that its name is rejected on 1883 and 8883.
-   [ ] For Tasmota devices using TLS: obtain the server certificate
    fingerprint, document it, and enter it in `MqttFingerprint1`.
-   [ ] Set up a reminder or monitoring for the server certificate's
    expiration date.

### Phase 6 – Go Security Service

-   [ ] Create repository `Noschvie/phylax-mqtt-security-service` with
    `LICENSE` (AGPL-3.0) and README (short description);
    add `// SPDX-License-Identifier: AGPL-3.0-or-later` to each Go source file.
-   [ ] Create Go module `github.com/Noschvie/phylax-mqtt-security-service` and
    package structure (`go.mod`, `cmd/`, `internal/`).
-   [ ] Implement MQTT connectivity using Eclipse Paho Go (MQTT 5, `autopaho`) and
    configure `crypto/tls` (Server CA, admin certificate
    `pmss-admin`, SAN verification, no username/password);
    use Clean Session and subscribe to the response topic
    in `OnConnectionUp` (A-9).
-   [ ] Implement DynSec command and response types using `encoding/json`.
-   [ ] Implement request/response correlation via `correlationData` (string,
    UUID), channels, and `context` timeouts robustly; after a
    timeout, read back instead of retrying; test concurrent requests
    (`go test -race`).
-   [ ] Implement the REST API using `net/http`/`ServeMux`, including validation,
    body limits, and server timeouts; return `409 certificate_client` for `enable`/`disable`
    on `CN=` clients (A-10).
-   [ ] Implement structured and audit logging with `log/slog`.
-   [ ] Implement bearer token verification using `go-oidc` as middleware:
    `oidc.NewVerifier`, fixed issuer, throttled `KeySet` from
    `PMSS_OIDC_JWKS_URL` or via discovery, `aud`, `exp`,
    required `scope` claim, `typ` check according to `PMSS_OIDC_TYP_CHECK`,
    scopes `read`/`write` (T-7 through T-9).
-   [ ] Write unit tests using an `httptest` test issuer for valid and
    invalid tokens.
-   [ ] Build an integration test environment (`test/integration/`) with
    Keycloak dev container (`KC_HOSTNAME`), test realm JSON, and
    Mosquitto (with `legacy-shared-user`).
-   [x] authentik probe (`test/integration/authentik`) with blueprint;
    as a separate job in `integration.yml`.
-   [ ] Create and test a Dockerfile locally (multi-stage, `golang:1.27-trixie` →
    `debian:trixie-slim`, non-root, `ca-certificates`, `tzdata`).
-   [ ] Add Compose configuration with read-only CA certificate and
    admin certificate.
-   [ ] Configure NPM reverse proxy and HTTPS.
-   [ ] Configure production OIDC provider (configuration as code): scopes
    `read`/`write` with audience set to the Security Service, `write` only
    for `security-admin`; TasmoFleet client with Token Exchange; client
    for the Device Authorization Grant; read-only service accounts;
    login flow with a second factor for `security-admin`. No
    service accounts with `write`. Keycloak: fixed hostname
    (`KC_HOSTNAME`). authentik: dedicated provider federated with the
    TasmoFleet provider and a policy for `write`; all callers use
    the same public URL (Section 7.5).
-   [ ] Decide for production whether the service loads keys over the
    internal network (`PMSS_OIDC_JWKS_URL`), and determine the shared network
    with the provider (Sections 4.2, 7.5).
-   [ ] Set up a GitHub Actions workflow: unit tests,
    integration tests, then multi-architecture image build and push to the
    GitHub Container Registry.

### Phase 7 – Refine permissions

-   [ ] Derive topic structures for each device and application from the inventory.
-   [ ] Define roles and groups.
-   [ ] Introduce least-privilege ACLs.
-   [ ] Remove the legacy role.
-   [ ] Verify default-deny for all relevant ACL types.

> **Note: cleanup after Phase 7**
> Once no client uses `role_legacy` or the shared password
> of `legacy-shared-user`, the rollback path using
> `password_file` is no longer needed. Then:
>
> - [ ] Delete `pwfile` and the `volumes/mosquitto/pwfile` directory,
>   along with its mount in the Compose file.
> - [ ] Remove commented-out `password_file` and `acl_file` lines and the
>   unused `filter.acl`.
> - [ ] Delete older backups containing `pwfile` and the old `mosquitto.conf`
>   after the retention period.
> - [ ] Delete log files from the observation week once profiles
>   have been derived.

## 10. Operations, backup, and recovery

At a minimum, back up:

-   `dynamic-security.json` – regularly by the host (e.g. daily
    and before deployments), independently of TasmoFleet and the Security
    Service. The backup is also the basis
    for break-glass recovery.
-   Mosquitto configuration
-   TLS server certificate and private key
-   Certificates of the server CA, Admin CA, and App CA
-   External server certificate (8883, 8885) and key
-   Admin certificate `pmss-admin` and key, and
    Security Service configuration
-   Break-glass certificate `pmss-breakglass-admin` and key,
    offline
-   Secure offline backup of all CA private keys

The Security Service image itself does not need to be backed up. It is
reproducibly buildable from source; the image tag or digest of the
production version is documented.

`dynamic-security.json` contains security-relevant information and
must be protected accordingly. Backups must not be publicly
accessible.

**Rollback path for the first migration:** `pwfile` remains unchanged
until cleanup after Phase 7. Restoring the backed-up `mosquitto.conf`
and then restarting returns the system to the state before DynSec;
devices do not need to be changed.

After recovery, verify:

1.  The broker starts with the restored DynSec file.
2.  Admin access by certificate works on 8884, but not on 1883.
3.  Existing clients can authenticate.
4.  Roles and ACLs are present.
5.  TLS/mTLS works with valid certificates, on 8883 and
    8885 with TLS 1.2 or higher.

## 11. Risks and open issues

| Topic | Risk / clarification needed |
|---|---|
| Shared password | The hash from `pwfile` is carried over; the shared password of `legacy-shared-user` remains valid until individual credentials are introduced (same residual risk as today). |
| Hash format | `import-pwfile.py` accepts only `$7$`. New entries stored in `pwfile` using another format (e.g. argon2id) would need to be re-evaluated. |
| Compatibility with existing setup | `role_legacy` represents the previous access to application topics, but not `$SYS/#`. Applications subscribing to `$SYS` lose this access (check in Phases 0 and 4). |
| Debug logs | Extensive, containing client IDs, usernames, and IP addresses; limit to one week, store securely, delete after Phase 7. |
| Syslog format | The inventory assumes that phylax-syslog-service writes one message per line. |
| Listener configuration | Tested with `plugin` (global) and `per_listener_settings false`. `plugin_load`/`plugin_use` has not been tested and is not used until then. |
| DynSec admin permissions | The service needs Control API permissions, but no permissions on regular MQTT topics. The `admin` role from `dynsec init` reads `#` and is therefore replaced by `role_security_manager` and deleted. |
| Admin CA | Whoever has the Admin CA key can issue admin certificates. Keep the key offline, issue only two admin certificates, disable via `deleteClient`. |
| Disabling admins | `disableClient` does not disable certificate authentication; the client retains its permissions. Disable only with `deleteClient` or by revoking roles (SEC-20). |
| Unknown CNs | A certificate from the Admin CA with an unknown CN can connect (without permissions). Controlled by the Admin CA issuance rule (SEC-18). The same applies to unknown subjects on 8885. |
| App CA | Whoever has the App CA key can issue certificates for any application and obtain its permissions, but never admin permissions (`use_subject_as_username`). Keep the key offline; TasmoFleet will later receive its own signing key (form open, Section 5.4). |
| Marker via `textdescription` | Whoever sets or removes the marker using `mosquitto_ctrl` (break-glass) changes what the Security Service is allowed to manage. This is intentional (adoption or protection), but must be done deliberately. |
| Provided passwords | A password chosen by the caller has the same format, but not necessarily the same randomness as a generated one. Normally, the Security Service generates the password. |
| CRL | Mosquitto checks a CRL only for the client certificate; revocation of an intermediate CA has no effect. A missing or (presumably) expired CRL for an issuing CA disables all its certificates. |
| Password on multiple listeners | Password clients can authenticate on 1883 and 8883; TLS cannot be enforced for them. It can be enforced only using App certificates (8885). |
| Tasmota and TLS | Tasmota verifies its own server CA only by fingerprint; each new server certificate (annually) requires a new fingerprint on the devices. Rotation uses `MqttFingerprint2` (Section 5.4); devices not reached lose their TLS connection. |
| Server certificate expiration | When the certificate expires, all TLS connections on 8883 and 8885 fail. Monitor the expiration date. |
| Network restrictions | Reachability on each network depends on router firewall rules, which are outside this project (SEC-24). |
| `mosquitto_ctrl` | Exit code 0 even for `Not authorized`; scripts and break-glass procedures must check the output. |
| mTLS | Certificate SAN, Docker DNS name, UID/GID, and file permissions must be correct. |
| REST security | HTTPS protects transport; token verification (signature, `iss`, `aud`, `exp`, `scope`, scopes) must be fully implemented and covered by negative tests. `go-oidc` does not check `typ`, `scope`, or scopes; the service handles this (T-7, T-9). |
| JWKS retrieval | Tokens with an unknown `kid` trigger a JWKS fetch from the provider. Limited to one fetch per minute (T-7). |
| Fixed issuer | Keycloak: without a fixed `KC_HOSTNAME`, `iss` depends on the request hostname. authentik: `iss` always depends on the request hostname. If a caller obtains its token using another name (e.g. internal), the service rejects it with `401` (T-8, SEC-40). |
| Key retrieval over internal network | If `PMSS_OIDC_JWKS_URL` uses HTTP over the Docker network, an attacker on that network could inject their own keys and forge tokens. This is the same trust boundary as the proxy hop from NPM to the service (Section 7.5). Only the required containers are attached to the network with the provider (SEC-39). |
| Discovery fallback | Without `PMSS_OIDC_JWKS_URL`, the service reads `jwks_uri` from the issuer's discovery document via the public URL. A different `issuer` in the document causes rejection (T-7). |
| Token type with authentik | Without a `typ` check (authentik), the service distinguishes access and ID tokens only by `scope` and audience. The Security Service provider must therefore have no `openid` mapping (T-9). |
| `azp` with authentik | In the exchanged token, `azp` is the Security Service, not TasmoFleet. The audit relies on `sub` and `preferred_username` (T-7). |
| `write` without `security-admin` with authentik | authentik rejects the entire request (`400 invalid_grant`) instead of omitting `write`; the message does not differ from other rejections. TasmoFleet requests `write` only for `security-admin` and falls back to `read` once (Specification S-16). |
| Time | `exp` is checked without tolerance; if the provider and broker host clocks differ, valid tokens are rejected. Synchronize both hosts using NTP. |
| Second factor only in provider | The service does not check `acr`/`amr`. A misconfigured login flow (e.g. a login path without a condition) would allow `write` without a second factor. Configuration as code, review checks, and manual test per provider (Section 7.9). |
| authentik app passwords | An app password provides a user token without browser login. If it can be exchanged for a token with `write`, the second factor is bypassed. Test F-7 deferred; possible mitigations in `test/integration/authentik/SECOND-FACTOR.md`. |
| ~~Client-scope role mapping~~ | ✅ Resolved: Keycloak 26.8.2 does not grant `write` without `security-admin`, including to service accounts (integration test, Section 7.9). |
| Token Exchange | TasmoFleet needs a client secret for the exchange; whoever has it can exchange user tokens for service tokens, but only with the respective user's permissions. |
| Provider availability | If the OIDC provider is unreachable, no new tokens can be issued; cached JWKS keys still allow valid tokens to be verified. `pmss-breakglass-admin` remains available for emergencies. |
| Docker host | A compromised or privileged Docker host can access container networks and keys. |
| Partial success in API calls | Multiple DynSec commands do not form a transaction. Compensation path for `POST /api/v1/clients` (Section 7.4) and `POST /api/v1/roles` (Section 7.3); ACL lists are replaced using `modifyRole` in one command. |
| Silent omission in `modifyRole` | DynSec does not report an error for invalid ACL entries. Mitigated by custom validation and readback (SEC-30). |
| `If-Match` race window | A change via `mosquitto_ctrl` can occur between checking and modifying; the window is short, and DynSec does not support conditional updates. |
| Concurrent password changes | A password change does not change the ETag (S-5, confirmed at the broker); two simultaneous changes for the same client both succeed. TasmoFleet permits only one in-progress password change per client (Specification 4.4). |
| Deviation from the specification | PMSS and the specification may diverge. The tests in 7.9 verify the specification; deviations are fixed in the specification or code, not documented. |
| Diff and approval in TasmoFleet | A bug in TasmoFleet could incorrectly modify managed objects. Mitigated by prefix/marker, validation, `If-Match`, audit with before state, and host backup. |
| Audit | Changes must be logged without collecting sensitive data. |
| ~~Paho Go / MQTT 5~~ | ✅ Tested (Section 7.2): `autopaho` does not resubscribe after reconnect; pending requests end only at their timeout; with a session, unconfirmed commands are retried and executed twice. Handling per A-9. |
| ~~Correlation~~ | ✅ Tested (Section 7.2): `correlationData` is returned for each command, including on errors. |
| Unknown state after timeout | If a response is lost due to a disconnect, the command may still have been executed. Mitigated by readback and no automatic retry (A-9). |
| Responses to all subscribers | Every DynSec response, including client data, is sent to all clients with read access to the response topic. These are only clients with `role_security_manager` (SEC-19); the service discards foreign responses. |
| Invalid `correlationData` | A value that is not a string aborts the entire batch; the error response has no ID. The service always sets `correlationData` itself as a string. |
| Runtime image | The Debian Slim base (trixie) contains more packages than `scratch` and therefore requires regular image rebuilds via the GitHub workflow. |
| UID/GID | The Go container's non-root UID must be able to read the read-only mounted key files without making them world-readable. |

### Decisions by topic

The IDs are used in the overview and in the interface specification.
The rationales are provided in the respective sections.

> **Technology and build** (Sections 3.3, 7.7, 7.8)
> - ✅ Go (current version, currently 1.27); `net/http`, `encoding/json`, `crypto/tls`, `log/slog`
> - ✅ MQTT 5 with Eclipse Paho Go (`paho.golang`, `autopaho`); ❌ no fallback to MQTT 3.1.1
> - ✅ Runtime image `debian:trixie-slim` with `ca-certificates` and `tzdata`, non-root
> - ✅ Production images only from GitHub Actions (`ghcr.io`), multi-arch `amd64`/`arm64`
> - ✅ Project name Phylax MQTT Security Service, repository `Noschvie/phylax-mqtt-security-service`, license `AGPL-3.0-or-later`

> **API access and tests** (Sections 7.5, 7.9)
> - ✅ No web GUI; REST API only with bearer tokens from configured OIDC provider (tested: Keycloak, authentik), scopes `read`/`write`; ❌ no browser login, no sessions
> - ✅ T-1: Service checks scopes only; provider issues `write` only to `security-admin`; ❌ no role, group, or `acr`/`amr` checks in the service
> - ✅ T-2: TasmoFleet uses Token Exchange (RFC 8693) with the user's token at the same provider
> - ✅ T-3: Second factor only in the provider
> - ✅ T-4: No service accounts with `write` in production; administrators use Device Authorization Grant
> - ✅ T-5: No audit endpoint; TasmoFleet maintains the audit of approvals
> - ✅ T-6: `GET /api/v1/export` with scope `read`
> - ✅ T-7: JWT verification with `coreos/go-oidc/v3` via `oidc.NewVerifier` and custom throttled `KeySet`; JWKS from `PMSS_OIDC_JWKS_URL`, otherwise `jwks_uri` via discovery with issuer verification; ❌ no custom JWT implementation, ❌ no `oidc.NewProvider`
> - ✅ T-8: Fixed issuer, exact `iss` comparison (Keycloak: `KC_HOSTNAME`; authentik: all callers use the same public URL); JWKS retrieval configured separately from issuer (`PMSS_OIDC_JWKS_URL`), can use internal network in production
> - ✅ T-9: `scope` claim required for every provider; `typ` check configurable (`PMSS_OIDC_TYP_CHECK`: `bearer` for Keycloak, `none` for authentik)
> - ✅ Unit tests with `httptest` test issuer, integration tests with Keycloak dev container and Mosquitto; test DynSec state as after bootstrap, with `legacy-shared-user` and `role_legacy`; authentik probe with blueprint, separate from Keycloak

> **Admin access to broker** (Sections 4.1, 5.1, 5.2, 6.2, 6.3)
> - ✅ E-1: Admin authenticates on 8884 using certificate only (`use_identity_as_username`); ❌ no admin password
> - ✅ E-2: Server CA and Admin CA; listener 8884 trusts only the Admin CA; mTLS mandatory
> - ✅ E-3: Two admin identities `pmss-admin` and `pmss-breakglass-admin`, role `role_security_manager`
> - ✅ E-4: Bootstrap admin from `dynsec init` and `admin` role are deleted
> - ✅ E-5: Bootstrap offline in a container without a network
> - ✅ E-6: Listener 8884 configured before DynSec activation
> - ✅ E-7: Plugin configuration as tested (`plugin` global, `per_listener_settings false`)
> - ✅ Disable using `deleteClient`; ❌ `disableClient` is not a way to disable certificate clients

> **Listeners and TLS** (Sections 4.1, 5.4)
> - ✅ L-1: TLS listener 8883 (password) as a separate phase after the functional test
> - ✅ L-2: Applications treated equally regardless of location; no special route through the Docker network
> - ✅ L-3: Network restrictions via firewall are outside this project; port matrix in Section 4.1
> - ✅ L-4: Server certificate for 8883/8885 from server CA (RSA, 12 months, renewed via `MqttFingerprint2`); no Let's Encrypt
> - ✅ L-5: “TLS required” = authentication using an App CA certificate without a password, listener 8885
> - ✅ L-6: `use_subject_as_username` on the app listener; naming rules prevent collisions
> - ✅ L-7: `tls_version tlsv1.2` minimum (Tasmota)
> - ❌ No listener mixing certificate and password authentication
> - ✅ App certificates initially issued manually, later through TasmoFleet; signing key form remains open (Section 5.4)

> **Initial migration** (Sections 2.2, 6.2, 6.5, 6.6, 9)
> - ✅ M-1: Carry over existing password hash; do not touch devices; ❌ no new password for all clients
> - ✅ M-2: Keep `pwfile` as rollback path; clean up after Phase 7
> - ✅ M-3: `role_legacy` permits everything under `#`, except `$SYS/#` and `$CONTROL/#`
> - ✅ M-4: Keep observation (after Phase 4) separate from restriction (Phase 7)
> - ✅ M-5: Observe for one week, then disable debug logging; centralized Syslog service as log destination (e.g. phylax-syslog-service)
> - ❌ Do not use `migrate_to_dynsec.py`

> **Names and passwords** (Sections 5.2, 6.4, 7.3)
> - ✅ N-1: Prefix `tf_` for roles and groups, marker `managed-by: pmss` for clients; username = Tasmota topic; ❌ no prefix in client usernames
> - ✅ N-2: Existing user (`legacy-shared-user`) and `role_legacy` remain unmanaged
> - ✅ N-3: Successors to admin identities receive a sequential number
> - ✅ N-4: TasmoFleet blocks devices with an invalid topic
> - ✅ N-5: Password optionally provided by caller, otherwise generated by PMSS
> - ✅ N-6: Passwords use only `A–Z a–z 0–9`, exactly 24 characters

> **API scope and state** (Sections 7.1, 7.2, 7.3, 7.4, 7.6, 10)
> - ✅ A-1: Diff and approval in TasmoFleet; ❌ no storage, change plans, or approval in the Security Service
> - ✅ A-2: `GET /api/v1/export` with all managed objects
> - ✅ A-3: Host regularly backs up `dynamic-security.json`
> - ✅ A-4: `PUT /api/v1/roles/{role}/acls` via `modifyRole`; retain `POST`/`DELETE` for individual ACLs
> - ✅ A-5: `ETag`/`If-Match`, `412` on mismatch
> - ✅ A-6: Audit with before and after state, without passwords
> - ✅ A-7: ACL fields: `allow` required, `priority` optional, warning for questionable deny priority
> - ✅ A-8: Compensation on partial success
> - ✅ A-9 (Specification S-13): MQTT connection with Clean Session, subscription in `OnConnectionUp`, timeout per request, read back rather than retry
> - ✅ A-10 (Specification Section 4): `enable`/`disable` for certificate clients → `409 certificate_client`, no broker command; disable only via `DELETE` and a new subject; ❌ do not map `disable` to role revocation

> **Interface specification** (Section 7.3)
> - ✅ I-1: REST API implements interface specification v1; the specification takes precedence in case of discrepancies
> - ✅ I-2: Paths `/api/v1/…`, endpoint `GET /api/v1/info`
> - ✅ I-3: Errors according to RFC 9457 with fixed error codes
> - ✅ I-4: Sorted export, `authType`, ETag based only on owned fields
> - ✅ I-5: `POST /api/v1/roles` with ACLs; association returns the modified object
> - ✅ I-6: Body limit at least 1 MiB; device roles `tf_role_dev_<mac>`

### Open issues

-   [ ] Test the bootstrap using the production image `eclipse-mosquitto:2.1.2`
    and `--network none` (so far tested with Mosquitto 2.1.2 from
    source and a listener bound only to `127.0.0.1`).
-   [ ] Production: choose key retrieval over the internal network
    (`PMSS_OIDC_JWKS_URL`) or public URL; determine the
    shared network with the provider (Sections 4.2, 7.5).
-   [x] Implement `PMSS_OIDC_TYP_CHECK` and the required `scope` claim in
    code (T-9).
-   [x] Keycloak: verify that ID tokens do not carry a `scope` claim
    (basis for T-9; `test/integration/keycloak/check_tokens.py`).
-   [ ] Manually test the second factor: Keycloak
    (`test/integration/keycloak/SECOND-FACTOR.md`); authentik (F-7)
    deferred until an authentik instance is available.
-   [x] authentik probe as a separate job in `integration.yml`; part of the
    release gate before image build.
-   [ ] Before the TasmoFleet development stage: choose an intermediate CA under
    the App CA with CRL or a dedicated TasmoFleet CA (Section 5.4). For the intermediate CA,
    test `nameConstraints` and behavior with an expired CRL.
-   [ ] Check the Syslog service's log format against a real Mosquitto log
    using `mqtt-acl-verify inventory`.

## 12. Acceptance criteria

The first production migration step is considered successful when:

-   [ ] DynSec is enabled on Mosquitto 2.1.2.
-   [ ] `password_file` and `acl_file` are no longer used for
    authentication or ACL checks.
-   [ ] `allow_anonymous false` remains in effect.
-   [ ] The existing MQTT user can connect with the existing
    password; no changes have been made to devices or applications.
-   [ ] `legacy-shared-user` has no access to `$SYS/#` or
    `$CONTROL/#`.
-   [ ] `pwfile` remains unchanged; the rollback path has been tested.
-   [ ] Mosquitto logs arrive at phylax-syslog-service.
-   [ ] Existing MQTT functionality is available after restart.
-   [ ] DynSec changes take effect without restarting the broker.
-   [ ] DynSec changes persist across a broker restart.
-   [ ] A backup and tested rollback path are available.
-   [ ] DynSec admins cannot authenticate on 1883.
-   [ ] No DynSec client with admin permissions and a password
    exists, and the `admin` role does not exist.
-   [ ] `pmss-breakglass-admin` can manage DynSec through 8884 but has
    no access to application topics.

Phase 5 (TLS listeners) is considered accepted when:

-   [ ] Clients with passwords on 8883 over TLS have the same permissions as on
    1883.
-   [ ] On 8885, only certificates from the App CA are accepted and the
    username matches the subject.
-   [ ] An app certificate with `CN=pmss-admin` receives no admin permissions.
-   [ ] Certificate clients cannot authenticate on 1883 or 8883.
-   [ ] TLS versions below 1.2 are rejected.
-   [ ] Clients connect via `mqtt.example.org` and pass
    hostname verification.

The Phylax MQTT Security Service (Go) is considered accepted when, in addition:

-   [ ] The REST API is reachable only through the intended HTTPS entry point.
-   [ ] The service reaches Mosquitto only through the internal Docker network
    and TLS/mTLS.
-   [ ] Port 8884 is not published on the host.
-   [ ] Invalid client certificates and certificates from CAs other than the
    Admin CA are rejected.
-   [ ] The service rejects a broker certificate with an incorrect SAN or a
    foreign CA.
-   [ ] Only callers with a valid bearer token from the OIDC provider and
    scope `write` can perform modifying actions; a token with only
    `read` receives `403` for modifying requests, and no token yields `401`.
-   [ ] All callers obtain tokens with the same `iss`, and the
    service accepts them (Keycloak: via public URL and
    internal network; authentik: via public URL).
-   [ ] Unit and integration tests (Keycloak dev container,
    Mosquitto) pass in the GitHub workflow before image build.
-   [ ] All endpoints in interface specification v1 work
    as described there, including status codes, error codes,
    `ETag` rules, and export sorting.
-   [ ] The production image comes from the GitHub Actions workflow
    (`ghcr.io`), not a local build.
-   [ ] API errors, timeouts, and partial success are handled and
    logged correctly.
-   [ ] Concurrent REST requests are correctly correlated with DynSec responses
    (tests including `go test -race`).
-   [ ] After a broker disconnect, the response topic is
    resubscribed and no command is executed twice.
-   [ ] The container runs on Debian Slim as non-root, and
    CA and admin certificates are mounted read-only only.
-   [ ] Logs are structured (`log/slog`, JSON) and contain
    no passwords, tokens, or keys.

## 13. References

-   Interface specification “MQTT Security Service API v1” –
    `mqtt-security-service-api-v1` (current version)
-   Architecture overview – `mqtt-security-overview` (current version)
-   [RFC 9457 – Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
-   [RFC 6750 – Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
-   [RFC 6901 – JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901)
-   [RFC 8693 – OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
-   [RFC 9110 – HTTP Semantics (`ETag`, `If-Match`)](https://www.rfc-editor.org/rfc/rfc9110)
-   [Eclipse Mosquitto – Dynamic Security
    Plugin](https://mosquitto.org/documentation/dynamic-security/)
-   [Eclipse Mosquitto – Dynamic Security API /
    README](https://github.com/eclipse-mosquitto/mosquitto/blob/master/plugins/dynamic-security/README.md)
-   [Eclipse Mosquitto – Listeners and per-listener
    settings](https://www.mosquitto.org/documentation/listeners/per-listener-settings/)
-   [Eclipse Mosquitto –
    TLS configuration](https://mosquitto.org/man/mosquitto-tls-7.html)
-   [Eclipse Mosquitto –
    Authentication methods](https://mosquitto.org/documentation/authentication-methods/)
-   [Eclipse Mosquitto 2.1.2 – source code for `dynsec init` and checking
    `disabled`](https://github.com/eclipse-mosquitto/mosquitto/tree/v2.1.2/plugins/dynamic-security)
    (`apps/mosquitto_ctrl/dynsec.c`, `plugins/dynamic-security/auth.c`)
-   [Eclipse Mosquitto 2.1.2 – Control API source code
    (`correlationData`, sending responses)](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/src/control_common.c)
-   [Eclipse Mosquitto 2.1.2 –
    `migrate_to_dynsec.py`](https://github.com/eclipse-mosquitto/mosquitto/blob/v2.1.2/plugins/dynamic-security/migrate_to_dynsec.py)
    (not used, see Section 6.2)
-   [Docker – Logging driver
    syslog](https://docs.docker.com/engine/logging/drivers/syslog/)
-   [mqtt-acl-verify – test broker
    `testbroker-dynsec/`](https://github.com/Noschvie/mqtt-acl-verify)
    (`cases-mtls.yaml`, cases `p-*`, `t-*`, `app-*`; `cases-dynsec.yaml`,
    cases `legacy-*`; `import-pwfile.py`; Control API
    `tests/test_dynsec_control.py`; `autopaho` probe
    `probes/autopaho-reconnect/`; docs `docs/testbroker-dynsec.md`)
-   [phylax-mqtt-security-service – Keycloak integration test
    `test/integration/keycloak`](https://github.com/Noschvie/phylax-mqtt-security-service/tree/main/test/integration/keycloak)
    (realm `pmss-test`, `check_tokens.py`, `SECOND-FACTOR.md`)
-   [phylax-mqtt-security-service – authentik probe
    `test/integration/authentik`](https://github.com/Noschvie/phylax-mqtt-security-service/tree/main/test/integration/authentik)
    (blueprint `pmss-test.yaml`, `check_tokens.py`, `SECOND-FACTOR.md`)
-   [Eclipse Paho Go – MQTT 5 (paho.golang)](https://github.com/eclipse-paho/paho.golang)
    (tested with v0.23.0)
-   [coreos/go-oidc – OpenID Connect for Go](https://github.com/coreos/go-oidc)
    (tested with v3.21.0; probe `test/probes/jwt-go-oidc` in the
    phylax-mqtt-security-service repository)
-   [Go – net/http](https://pkg.go.dev/net/http)
-   [Go – crypto/tls](https://pkg.go.dev/crypto/tls)
-   [Go – log/slog](https://pkg.go.dev/log/slog)
-   [Go – encoding/json](https://pkg.go.dev/encoding/json)
-   [Keycloak – Server administration (Client Credentials, Device Authorization Grant, Client Scopes)](https://www.keycloak.org/docs/latest/server_admin/)
-   [Keycloak – realm import on startup](https://www.keycloak.org/server/importExport)
-   [Keycloak – hostname (`KC_HOSTNAME`)](https://www.keycloak.org/server/hostname)
-   [Keycloak – Token Exchange](https://www.keycloak.org/securing-apps/token-exchange)
-   [authentik – OAuth2 provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/)
-   [authentik – Token Exchange](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/token_exchange/)

------------------------------------------------------------------------

**Review note:** This document describes the intended
design and migration path. It is not a configuration to be executed.
In particular, the specific listener/plugin configuration, the
DynSec ACLs, the Docker network connection, and the Go/container examples
must be validated in the existing IOTstack environment before production use.
