# Integration tests

The integration tests of the design document (section 7.9) in one compose environment, [`compose.yaml`](compose.yaml):

| Service | Image | Host port | Role |
|---|---|---|---|
| `keycloak` | Keycloak 26.8.2, realm [`pmss-test`](keycloak/README.md) | 8180, 8190 (health) | Token issuer |
| `mosquitto` | Mosquitto 2.1.2 with Dynamic Security, [test PKI](broker/README.md) | 18883 (password), 18884 (admin, mTLS) | Broker |
| `pmss` | Built from this repository, read-only, certificates read-only | 18080 | Service under test |

The service uses the production defaults (`mqtts://mosquitto:8884`, certificate paths under `/run`). Only the token check is configured: issuer `http://127.0.0.1:8180/realms/pmss-test`, JWKS via `keycloak:8080` (`PMSS_OIDC_JWKS_URL`), http allowed for the test.

## Run

```sh
cd test/integration
broker/make-certs.sh broker/run      # test PKI and DynSec state, not in git
docker compose up -d --build --wait
until curl -sf http://127.0.0.1:8190/health/ready >/dev/null; do sleep 3; done
docker compose logs -f --no-log-prefix pmss > pmss.log &

cd ../..
PMSS_TEST_KEYCLOAK=http://127.0.0.1:8180 \
PMSS_TEST_BROKER_URL=mqtts://127.0.0.1:18884 \
PMSS_TEST_BROKER_PLAIN=127.0.0.1:18883 \
PMSS_TEST_BROKER_CERTS=$PWD/test/integration/broker/run/certs \
PMSS_TEST_E2E_URL=http://127.0.0.1:18080 \
PMSS_TEST_E2E_LOG=$PWD/test/integration/pmss.log \
  go test -race -count=1 -p 1 ./internal/... ./test/integration/e2e/

cd test/integration && docker compose down -v
```

`-p 1` runs the packages one after the other: they share one broker, and the export test (`internal/api`) compares two exports of all managed objects, which objects of a parallel package would change. Every test package skips its integration tests when its variables are missing, so `go test ./...` without the environment stays a pure unit test. CI runs the same steps in [`.github/workflows/integration.yml`](../../.github/workflows/integration.yml), plus `keycloak/check_tokens.py`, the JWT probe and a graceful shutdown of the service (exit code 0 after `SIGTERM`). The [authentik probe](authentik/README.md) runs as a separate job `authentik-probe` in the same workflow; both jobs gate the image build.

## What runs

| Package | Variables | Checks |
|---|---|---|
| `internal/dynsec`, `internal/mqttclient`, `internal/api` | `PMSS_TEST_BROKER_*` | Broker connection (mTLS, correlation, reconnect, broker down), write flow and extras against the real broker, login of created clients |
| `internal/auth` | `PMSS_TEST_KEYCLOAK` | Token check of the service against Keycloak tokens |
| [`test/integration/e2e`](e2e/e2e_test.go) | `PMSS_TEST_E2E_URL`, `PMSS_TEST_KEYCLOAK`, optional `PMSS_TEST_BROKER_PLAIN`, `PMSS_TEST_E2E_LOG` | Whole path against the running service, see below |

Test cases of `e2e` (design 7.9):

| Test | Expected |
|---|---|
| No token, broken token | `401 invalid_token` with `WWW-Authenticate` |
| `msm-test-ro` | `GET /api/v1/info` with `apiVersion` 1.x and `maxRequestBytes` ≥ 1 MiB; `POST` → `403 insufficient_scope` |
| `msm-test-rw-norole` (write in the client, no `security-admin`) | `POST` → `403` |
| Access, ID and refresh token of TasmoFleet itself | `401` |
| Token exchange for `alice` (`security-admin`) | Group created and deleted; audit record with `username` alice and `azp` `tasmofleet-test` |
| Token exchange for `bob` | `GET` allowed, `DELETE` → `403` |
| `msm-test-rw`: role with `cmnd/%u/#`, client with this role | Generated password (24 characters, `no-store`); the client logs in and gets exactly its subscriptions |
| Export | Contains the new client and role, not `legacy-shared-user` or `pmss-admin` |
| `legacy-shared-user`, `pmss-admin` | `403 not_managed`, `403 reserved_name` |
| Body over 1 MiB | `413 payload_too_large` |
| Delete | The client can no longer log in |
| Log (`PMSS_TEST_E2E_LOG`) | No token and no password of the test in the service log |

Locally without Docker the same tests run against a native Keycloak (`kc.sh start-dev --import-realm` with `KC_HOSTNAME=http://127.0.0.1:8180`, `KC_HTTP_PORT=8180`, `KC_HTTP_MANAGEMENT_PORT=8190`), a native Mosquitto and the binary started with the variables of `compose.yaml`. With Mosquitto 2.0 the `%u` check is skipped.
