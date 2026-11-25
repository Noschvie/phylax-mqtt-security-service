# Keycloak integration test

Checks the Keycloak part of the integration tests from the design document (section 7.9) against **Keycloak 26.8.2**, the production version. The Security Service itself is not involved yet: the test checks what Keycloak puts into the tokens.

| File | Content |
|---|---|
| `realm/pmss-test-realm.json` | Test realm `pmss-test`, imported at startup |
| `compose.yaml` | Keycloak 26.8.2 in dev mode with realm import |
| `check_tokens.py` | Token checks, Python standard library only |
| `SECOND-FACTOR.md` | Manual test of the second factor with browser and device code |

## Run

```sh
cd test/integration/keycloak
docker compose up -d
until curl -sf http://127.0.0.1:8190/health/ready >/dev/null; do sleep 3; done
python3 check_tokens.py
docker compose down -v
```

Expected: 10 × `PASS`, exit code 0. CI runs the same check in the combined environment ([../README.md](../README.md), `.github/workflows/integration.yml`).

`KC_HOSTNAME` fixes the issuer to `http://127.0.0.1:8180/realms/pmss-test`, whatever host name a request uses. Tests on the host get their tokens via `127.0.0.1:8180`; the service in the compose network fetches the JWKS via `keycloak:8080`.

## Test realm

| Object | Configuration |
|---|---|
| Client scopes `read`, `write` | Audience mapper on the Security Service (`phylax-mqtt-security-service`) |
| Scope `write` | Role scope mapping on realm role `security-admin`: only users and service accounts with this role get `write` |
| Client scope `basic` | Mappers for `sub` and `preferred_username` (see below) |
| `phylax-mqtt-security-service` | Target client of the audience; no login |
| `msm-test-rw` | Service account with `read`, `write` and role `security-admin` |
| `msm-test-ro` | Service account with `read` only |
| `msm-test-rw-norole` | Service account with `read`, `write`, **without** `security-admin` (checks the role mapping) |
| `tasmofleet-test` | Confidential client, Standard Token Exchange enabled, `read`/`write` as optional scopes, password grant for the test users (test only) |
| `pmss-api-tester` | Confidential client for the read-only API tester: authorization code with PKCE, Standard Token Exchange, only `read` as optional scope; redirect URI from `PMSS_API_TESTER_URL` (default `http://127.0.0.1:8080`), secret `pmss-api-tester-secret` |
| `pmss-cli` | Public client, device authorization grant only, `read`/`write` as optional scopes (administrator via `curl`) |
| Browser flow `browser-security-admin-2fa` | OTP for realm role `security-admin`, set up at the first sign-in; also for the device sign-in ([SECOND-FACTOR.md](SECOND-FACTOR.md)) |
| Users `alice`, `bob` | `alice` with `security-admin`, `bob` without; password = username; no OTP at import, so the password grant works without `totp` |

All secrets are fixed test values. The realm exists only for these tests.

## Checks

| Check | Expected |
|---|---|
| `msm-test-rw`, client credentials | `scope` = `read write`, `aud` = Security Service |
| `msm-test-ro` | `read` only |
| `msm-test-ro` requests `write` | `400 invalid_scope` |
| Service account with scope `write` but without `security-admin` | no `write` |
| Original TasmoFleet token of a user | `aud` does not contain the Security Service |
| Token exchange for `alice` (`security-admin`) | `aud` = Security Service only, `read write`, `sub` and `preferred_username` = alice |
| Token exchange for `bob` (no `security-admin`) | no `write` |
| Token exchange for `bob`, scope `read` | `read`, `aud` = Security Service, user = bob |
| Token exchange to an audience no scope provides | `400 Requested audience not available` |
| Token issued to another client, exchanged by `tasmofleet-test` | `403 Client is not within the token audience` |

## Findings (Keycloak 26.8.2)

- **A missing `write` is not an error.** For a user without `security-admin`, the token exchange returns `200` with `scope=read`. TasmoFleet must check the `scope` of the exchanged token instead of relying on an error.
- **Service accounts need the role too.** A service account with `write` as default scope but without `security-admin` gets no `write`.
- **Built-in client scopes are not created** when the realm JSON contains its own `clientScopes` list (`basic`, `profile`, `roles` …). `sub` is still in the token, `preferred_username` is not. The realm therefore defines `basic` with both mappers; the audit of the Security Service needs the username.
- **TasmoFleet can only exchange tokens issued to it.** A token of another client is refused.
