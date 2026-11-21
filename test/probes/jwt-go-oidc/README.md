# JWT verification with go-oidc

Probe for the JWT library of the Security Service (design section 7.5, SEC-15): [`coreos/go-oidc/v3`](https://github.com/coreos/go-oidc) v3.21.0 with `go-jose/v4`.

`verifier.go` is the template for `internal/auth`: go-oidc checks signature, `iss`, `aud`, `exp`, `nbf` and the algorithm; PMSS adds the token type, the scopes and a throttled JWKS refresh.

| File | Content |
|---|---|
| `verifier.go` | `Verifier` (go-oidc plus `typ` and `scope`), `ThrottledKeySet` |
| `verifier_test.go` | Tests against a local test issuer (`httptest`, own RSA and EC keys) |
| `keycloak_test.go` | Tests against the test realm of `test/integration/keycloak` (Keycloak 26.8.2) |

## Run

```sh
cd test/probes/jwt-go-oidc
go mod tidy                      # first run: creates go.sum
go test -race -v ./...           # local test issuer only

# with Keycloak (see test/integration/keycloak/README.md)
PMSS_TEST_KEYCLOAK=http://127.0.0.1:8180 go test -race -v ./...
```

CI runs both in `.github/workflows/keycloak-integration.yml`.

## Results (go-oidc v3.21.0)

| Case | Result |
|---|---|
| Access token with `aud` = [Security Service, `account`] | ✅ accepted; `aud` is checked as "contains" |
| Wrong `iss`, `aud` without the Security Service, `aud` missing | ❌ rejected |
| `exp` 1 s in the past | ❌ rejected – **no leeway** on `exp` |
| `nbf` 10 min in the future | ❌ rejected |
| `nbf` 2 min in the future | ✅ accepted – **fixed leeway of 5 min** on `nbf`, not configurable |
| Other key with the same `kid`, payload changed after signing | ❌ rejected |
| `alg: none`, `HS256` with the public key as secret | ❌ rejected (algorithm list) |
| `ES256` token with the algorithm list `[RS256]` | ❌ rejected |
| `azp` of any other client | ⚠️ accepted – go-oidc does not check `azp` |
| Keycloak ID token (`typ: ID`) whose `aud` contains the Security Service | ⚠️ accepted by go-oidc alone; rejected by the `typ` check of `verifier.go` |
| New key published (rotation) | ✅ picked up on the first token with the new `kid` |
| 10 tokens with unknown `kid` | ⚠️ go-oidc's `RemoteKeySet` fetches the JWKS **10 times**; `ThrottledKeySet` fetches at most once per interval |

Against Keycloak: `msm-test-rw` has `read write`, `msm-test-ro` only `read`, the exchanged token of `alice` carries her username and `write`, that of `bob` no `write`; the original TasmoFleet token (wrong `aud`), the ID token and the refresh token are rejected.

## Consequences for PMSS

- go-oidc with `ClientID` = audience of the Security Service and `SupportedSigningAlgs` = `RS256`, `ES256`.
- PMSS checks `typ == "Bearer"` itself; otherwise an ID token with a matching `aud` would pass.
- Scopes come from the `scope` claim (space separated); go-oidc does not read it.
- JWKS via an own `oidc.KeySet` that refreshes for an unknown `kid` at most once per minute.
- `azp` and `preferred_username` only for the audit, not for the decision.
- Clocks of Keycloak and PMSS must be in sync (NTP): `exp` has no leeway.
