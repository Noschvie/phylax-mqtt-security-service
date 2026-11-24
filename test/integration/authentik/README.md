# authentik probe

Step 1 of the plan to support authentik next to Keycloak (`pmss-authentik-plan`): the token checks of the [Keycloak integration test](../keycloak/README.md) against **authentik 2026.8.6**. The Security Service itself is not involved: the probe checks what authentik puts into the tokens and answers the open questions F-1 to F-8 of the plan as far as they can be automated. Not part of CI yet.

| File | Content |
|---|---|
| `blueprints/pmss-test.yaml` | Providers, applications, users, scopes and policy, applied at startup |
| `compose.yaml` | authentik (server, worker) and PostgreSQL |
| `make-keys.sh` | Signing key of the test providers in `run/` (not committed) |
| `check_tokens.py` | Token checks, Python standard library only |

## Run

```sh
cd test/integration/authentik
./make-keys.sh
docker compose up -d
python3 check_tokens.py      # waits until the blueprint is applied (up to 10 min)
docker compose down -v
```

Expected: only `PASS` and `INFO` lines, exit code 0. Exit code 2: authentik did not answer or the blueprint was not applied; see `docker compose logs worker`. The admin interface is at `http://127.0.0.1:9180/if/admin/` (user `akadmin`, password `admin`), the blueprint under System → Blueprints.

Another version: `AUTHENTIK_TAG=2026.5.8 docker compose up -d`.

## Test configuration

| Object | Configuration | Keycloak counterpart |
|---|---|---|
| Provider `pmss`, client ID `phylax-mqtt-security-service` | Scope mappings `read` (adds `preferred_username`) and `write`; trusts `tasmofleet-test` (Federated OAuth2/OpenID Providers); grant `client_credentials` | Client `phylax-mqtt-security-service`, client scopes with audience mapper |
| Policy `pmss-test-write-requires-security-admin` on application `pmss` | Refuses a token request with scope `write` for users outside the group `security-admin` | Role scope mapping on `write` |
| Provider `tasmofleet-test` | Confidential, grants `authorization_code`, `refresh_token`, `client_credentials`, token exchange | Client `tasmofleet-test` with Standard Token Exchange |
| Provider `other-app` | Another application of the same users | – (negative test) |
| Group `security-admin` | `alice`, `msm-test-rw` | Realm role `security-admin` |
| Users `alice`, `bob` | App passwords `alice-app-password`, `bob-app-password` | Password grant |
| Service accounts `msm-test-rw`, `msm-test-ro`, `msm-test-rw-norole` | App passwords `<name>-secret`, tokens from provider `pmss` | Clients with service account |
| Keypair `pmss-test-signing` | RSA 2048 from `run/`, signs all three providers | Realm keys |

authentik has no password grant in the usual sense: `grant_type=client_credentials` with `username` and an app password stands in for it. All secrets are fixed test values.

## Checks

| Check | Expected |
|---|---|
| Signature and issuer | `RS256`, `kid` in the JWKS of `pmss`, `iss` = issuer of the discovery document |
| `msm-test-rw` | `read write`, `aud` = Security Service |
| `msm-test-ro`, scope `read` | `read` only |
| `msm-test-ro` and `msm-test-rw-norole` ask for `write` | no `write` (authentik refuses the request) |
| Original TasmoFleet token of `alice` | `aud` does not contain the Security Service |
| Token exchange for `alice` (`security-admin`) | `aud` = Security Service only, `read write`, `preferred_username` = alice, `sub` |
| Token exchange for `bob`, `read write` | no `write` |
| Token exchange for `bob`, `read` | `read`, `aud` = Security Service, user = bob |
| Exchange with `audience` = a provider that does not trust TasmoFleet | refused |
| Exchange of a token of the Security Service or of `other-app` | refused |

`INFO` lines record: `typ` in header and claims of access and ID tokens (F-2), form of the `scope` claim (F-3), `azp` and `act` of the exchanged token (F-4), issuer of the exchanged token (F-5), the answer to `write` without `security-admin` (F-1) and the issuer for another `Host` (T-8).

## Expected differences to Keycloak (from the authentik 2026.8.6 source)

To be confirmed by the run:

- **`write` without `security-admin`:** Keycloak answers `200` with `scope=read`. authentik grants every requested scope that has a mapping on the provider; only an application policy can stop it, and then the whole request fails (`400 invalid_grant`). TasmoFleet would have to ask for `read write` and fall back to `read`.
- **`typ`:** authentik sets no `typ` claim; the header carries the default `JWT`. The check of PMSS for `typ == "Bearer"` rejects every authentik token.
- **`azp`:** authentik sets `azp` to the client ID of the provider that issues the token, after an exchange with `audience` that is the Security Service, not TasmoFleet.
- **Issuer:** built from the host name of each request (`issuer_mode: per_provider`); authentik has no fixed host name like `KC_HOSTNAME`. All clients have to get their tokens over the same URL.
- **Not covered:** second factor and device code (F-7) need a browser; the minimum version (F-8) needs runs with older tags.
