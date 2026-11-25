# authentik probe

The token checks of the [Keycloak integration test](../keycloak/README.md) against **authentik 2026.8.6**. The Security Service itself is not involved: the probe checks what authentik puts into the tokens. It was written to decide whether and how PMSS supports authentik next to Keycloak (TasmoFleet supports an authentik login); the questions F-1 to F-8, the results and the decisions are recorded [below](#results-and-decisions). CI runs it as job `authentik-probe` in [`.github/workflows/integration.yml`](../../../.github/workflows/integration.yml), separate from the Keycloak job; like the Keycloak job it gates the image build in `release.yml`.

| File | Content |
|---|---|
| `blueprints/pmss-test.yaml` | Providers, applications, users, scopes and policy, applied at startup |
| `compose.yaml` | authentik (server, worker) and PostgreSQL |
| `make-keys.sh` | Signing key of the test providers in `run/` (not committed) |
| `check_tokens.py` | Token checks, Python standard library only |
| `SECOND-FACTOR.md` | Manual test of the second factor with browser and device code (F-7) |

## Run

```sh
cd test/integration/authentik
./make-keys.sh
docker compose up -d
python3 check_tokens.py      # waits until the blueprint is applied (up to 10 min)
docker compose down -v
```

Expected: only `PASS` and `INFO` lines, exit code 0. Exit code 2: authentik did not answer or the blueprint was not applied; see `docker compose logs worker`. The admin interface is at `http://127.0.0.1:9180/if/admin/` (user `akadmin`, password `admin`), the blueprint under System → Blueprints.

Another version (at least 2026.8.3, the first with a working token exchange): `AUTHENTIK_TAG=2026.8.3 docker compose up -d`.

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

## Results and decisions

### Questions and results

Probe run with authentik 2026.8.6 and PostgreSQL 18 on 24.11.2026: all checks passed.

| No. | Question | Result |
|---|---|---|
| F-1 | Can `write` be limited to members of `security-admin`? | ✅ With an expression policy on the application `pmss` (context `oauth_scopes`). Unlike Keycloak (`200` with `scope=read`), authentik refuses the **whole** request with `400 invalid_grant`; the error text does not differ from other refusals |
| F-2 | Which `typ` do access, ID and refresh tokens carry? | ⚠️ Header `typ: JWT`, **no** `typ` claim. Only the access token has `scope` and `uid`; the ID token of TasmoFleet has `aud` = `tasmofleet-test`; the provider `pmss` issues no ID tokens |
| F-3 | Does the access token have a `scope` claim, in which form? | ✅ String, separated by spaces (`"read write"`), as with Keycloak |
| F-4 | `sub`, `preferred_username`, `azp` in the exchanged token? | ⚠️ `sub` and `preferred_username` = user; `azp` = `phylax-mqtt-security-service` (the issuing provider, not TasmoFleet); no `act` (impersonation) |
| F-5 | Exchanged token: `iss`, `aud`, `scope`, `sub`? | ✅ `iss` = issuer of provider `pmss`, `aud` = `["phylax-mqtt-security-service"]`, `scope` as requested |
| F-6 | Exchange of a token of another client refused? | ✅ Target provider without trust in TasmoFleet (`invalid_target`), token of the Security Service, token of another application (`invalid_grant`) |
| F-7 | Does the second factor for `security-admin` also hold for token exchange and device code? | ⏸️ Deferred until an authentik instance is available; test case in [SECOND-FACTOR.md](SECOND-FACTOR.md) |
| F-8 | From which authentik version does the token exchange work? | ✅ Token exchange (RFC 8693) is new in 2026.8.0; 2026.8.3 fixes the exchange without signing key (PR #26049). Taken from release notes and documentation, not from runs |
| T-8 | Is the issuer fixed? | ⚠️ No: built from the `Host` of each request (`Host: authentik-server:9000` gives `iss` = `http://authentik-server:9000/application/o/pmss/`); no fixed host name like `KC_HOSTNAME` |

`grant_types_supported` in the discovery document is a fixed list without token exchange; it has no effect.

### Decisions

| No. | Decision | Where |
|---|---|---|
| E-A1 | Specification 1.1, backward compatible: any OIDC provider with token exchange (RFC 8693); Keycloak and authentik are the tested providers | Specification 2.1–2.3, S-15 |
| E-A2 | TasmoFleet asks for `write` only for members of `security-admin`; if refused, retries once with `read`; always evaluates `scope` of the exchanged token (F-1) | Specification 2.2, S-16 |
| E-A3, E-A11 | `scope` claim required for every provider; `typ` check configurable with `PMSS_OIDC_TYP_CHECK`: `bearer` (default, Keycloak) or `none` (authentik). Keycloak ID tokens carry no `scope` claim (checked in [`../keycloak/check_tokens.py`](../keycloak/check_tokens.py)) (F-2) | Design T-9, SEC-15 |
| E-A4 | The audit relies on `sub` and `preferred_username`; `azp` is optional extra information (F-4) | Design 7.5 |
| E-A5 | All callers get their tokens over the same public URL of the provider; the reverse proxy passes `Host`/`X-Forwarded-Host` through. PMSS may fetch the JWKS over the internal network (`PMSS_OIDC_JWKS_URL`) (T-8) | Specification 2.2, design T-8, SEC-40 |
| E-A6 | The Security Service is offered only with `TASMOFLEET_AUTH_MODE=oidc`; header mode and local accounts have no user token to exchange (also for Keycloak) | Specification 2.2, S-17 |
| E-A7 | TasmoFleet exchanges a valid access token of the session and refreshes it first if needed (`offline_access`) | Specification 2.2, S-17 |
| E-A8 | authentik: own provider and application for PMSS (client ID `phylax-mqtt-security-service`); it trusts the TasmoFleet provider (Federated OAuth2/OpenID Providers); `write` limited to group `security-admin` by an expression policy | Specification 2.3, design 7.5 |
| E-A9 | Minimum version authentik 2026.8.3, tested with 2026.8.6; CI tests only the current version (F-8) | Specification 2.3 |
| E-A10 | Without `PMSS_OIDC_JWKS_URL` the JWKS address comes from discovery (`jwks_uri`; the `issuer` of the document must match) | Design T-7 |
