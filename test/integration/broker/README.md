# Broker integration test

Mosquitto 2.1.2 with Dynamic Security for the tests of the broker connection (design sections 7.2 and 7.9). The admin listener is configured as in production: only certificates of the admin CA, the CN is the user name, no password.

| File | Content |
|---|---|
| `make-certs.sh` | Creates the test PKI and the broker data in `run/` (not committed) |
| `dynamic-security.json` | DynSec state after the offline bootstrap: default deny, `role_security_manager`, `pmss-admin` and `pmss-breakglass-admin` without password, `legacy-shared-user` (no password in the test) with `role_legacy` |
| `mosquitto.conf` | Admin listener 8884 with mTLS, password listener 1883 |
| `compose.yaml` | Mosquitto, admin listener on `127.0.0.1:18884`, password listener on `127.0.0.1:18883` |

The tests are in `internal/dynsec` and `internal/api` (`*integration_test.go`) and run only when `PMSS_TEST_BROKER_URL` is set. `PMSS_TEST_BROKER_PLAIN` additionally checks the login and the rights of clients created through the API.

## Run

```sh
cd test/integration/broker
./make-certs.sh
docker compose up -d
PMSS_TEST_BROKER_URL=mqtts://127.0.0.1:18884 \
PMSS_TEST_BROKER_PLAIN=127.0.0.1:18883 \
PMSS_TEST_BROKER_CERTS=$PWD/run/certs \
  go test -race -count=1 -p 1 -v -run Integration ../../../internal/...
docker compose down
```

## Test cases

| Test | Checks |
|---|---|
| `TestIntegrationCommands` | `listClients`, `getClient` (also: no password hash, S-5), `createClient`, `deleteClient`; plugin errors `not found` and `already exists` arrive with their `correlationData` |
| `TestIntegrationParallelTwoAdmins` | 80 parallel commands from `pmss-admin` and `pmss-breakglass-admin`; both get every response and keep only their own |
| `TestIntegrationReconnect` | TCP cut without DISCONNECT; after the reconnect the response topic is subscribed again and commands work (A-9) |
| `TestIntegrationBrokerDown` | No connection: `ErrUnavailable` after the command timeout; the command is not sent later |
| `TestIntegrationWrongCA` | A client certificate of the server CA is rejected at the admin listener |
| `TestIntegrationReadAPI`, `…PasswordChangeKeepsETag` | Export, single objects and ETag rules with real DynSec data |
| `TestIntegrationWriteFlow` | Roles with ACLs, group, client with generated password (login and SUBACK codes at the password listener), unknown role creates nothing, password change (old password refused), ACL replacement, `412` after a change by `mosquitto_ctrl`, delete |

The test keys are world-readable so that the broker container can read them. They exist only for one test run.
