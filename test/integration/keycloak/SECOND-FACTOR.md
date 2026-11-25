# Manual test: second factor for `security-admin` (Keycloak)

Manual test for SEC-36 with Keycloak 26.8.2: tokens with scope `write` only after a sign-in with a second factor, also for token exchange and the device authorization grant (design 7.5). It needs a browser and is not part of `check_tokens.py`.

> **What is tested**
> The token exchange itself is not interactive: Keycloak asks for no second factor during the exchange. The second factor has to apply at the **sign-in** the subject token comes from. The test therefore checks three things:
> 1. The browser sign-in (authorization code and device code) asks `security-admin` members for an OTP, and makes them set one up at the first sign-in.
> 2. A token from such a sign-in can be exchanged for, or used with, `write`.
> 3. **No path without a second factor** leads to a token with `write`. Critical is the password grant (direct access grants) of `tasmofleet-test`: it yields a user token without any browser sign-in. `check_tokens.py` and the e2e test use this path, so it stays enabled in the test realm.

## 1. Test realm

The realm [`pmss-test`](realm/pmss-test-realm.json) contains everything; no manual setup in the admin console.

| Object | Configuration |
|---|---|
| Browser flow `browser-security-admin-2fa` | Cookie, then username and password; for realm role `security-admin` an OTP (Condition - user role, OTP Form required). Users without OTP have to set one up at the first sign-in. Also used for the device sign-in |
| Client `pmss-cli` | Public, device authorization grant only, `read`/`write` as optional scopes (administrator via `curl`) |
| Client `pmss-api-tester` | Confidential, authorization code with PKCE, standard token exchange, `read`/`write` as optional scopes. Redirect URI `${PMSS_API_TESTER_URL}/auth/callback` (default `http://127.0.0.1:8080`); the client secret is generated at the import (admin console → Clients → `pmss-api-tester` → Credentials) |
| Client `tasmofleet-test` | Password grant enabled, **test only** (`check_tokens.py`, e2e). The built-in direct grant flow asks for an OTP only once the user has set one up |
| Users `alice`, `bob` | `alice` with `security-admin`, `bob` without; password = username; no OTP at import |

Start Keycloak as in the [README](README.md); for an API tester on another host:

```sh
PMSS_API_TESTER_URL=http://<tester-host>:8080 docker compose up -d
```

Use a private browser window and an authenticator app (TOTP, 6 digits, 30 s). The admin console is at `http://127.0.0.1:8180/admin/` (user `admin`, password `admin`).

> **Note**
> After `alice` has set up an OTP, `check_tokens.py` and the e2e test fail for `alice` (password grant without `totp`). Start over with `docker compose down -v`.

> **Note on PMSS**
> For the calls in the API tester, PMSS must be configured for this realm: issuer `http://127.0.0.1:8180/realms/pmss-test`, audience `phylax-mqtt-security-service`, as in the [combined environment](../README.md).

Variables:

```bash
KC=http://127.0.0.1:8180/realms/pmss-test/protocol/openid-connect
TF_ID=tasmofleet-test;  TF_SECRET=tasmofleet-test-secret
PMSS_ID=phylax-mqtt-security-service
```

Decode a token (payload):

```bash
jwt() { cut -d. -f2 <<<"$1" | tr '_-' '/+' | base64 -d 2>/dev/null; echo; }
```

## 2. Test cases

| No. | Steps | Expected | Result |
|---|---|---|---|
| K2F-1 | Sign-in `alice` in the API tester, first time | After the password: OTP setup (QR code); no token without it | |
| K2F-2 | Sign-in `alice` in the API tester, again (new private window) | After the password: OTP prompt | |
| K2F-3 | Sign-in `bob` in the API tester | No OTP setup, no OTP prompt | |
| K2F-4 | Exchange in the API tester after K2F-2, `scope=read write`, then a `write` call | Exchanged token: `aud` = Security Service, `scope` = `read write`, user `alice`; PMSS call `2xx` | |
| K2F-5 | Same for `bob` | Exchange `200` with `scope` = `read` (Keycloak drops `write`); `write` call `403` | |
| K2F-6 | **Bypass:** password grant `alice` at `tasmofleet-test` **before** K2F-1 (fresh realm), then exchange with `write` | Token with `read write` without a second factor → known gap of the test realm; production: direct access grants disabled on every client | |
| K2F-7 | Password grant `alice` **after** K2F-1, without `totp` | `401 invalid_grant` | |
| K2F-8 | Device code `alice` at `pmss-cli`, `scope=read write` | OTP prompt (or setup) in the browser, then consent; token with `read write`, `aud` = Security Service | |
| K2F-9 | Device code `alice`, close the browser at the OTP prompt | Polling stays `authorization_pending`, then `expired_token`; no token | |
| K2F-10 | Device code `bob`, `scope=read write` | No OTP; token with `scope` = `read` | |

## 3. Steps

### K2F-1 to K2F-5 – API tester

Configure the API tester with issuer `http://127.0.0.1:8180/realms/pmss-test`, client `pmss-api-tester` and its secret from the admin console. Sign in, watch for OTP setup and prompt, then let the tester exchange the token for audience `phylax-mqtt-security-service` with `scope=read write` and run a harmless `write` call, e.g. create client `tf_k2f-probe` and delete it again.

### K2F-6 / K2F-7 – password grant

```bash
PW=$(curl -s "$KC/token" -d grant_type=password -d client_id="$TF_ID" -d client_secret="$TF_SECRET" \
  -d username=alice -d password=alice -d scope=openid)
echo "$PW" | jq '{error, error_description}'
SUBJ=$(jq -r .access_token <<<"$PW")

XCH=$(curl -s "$KC/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id="$TF_ID" -d client_secret="$TF_SECRET" \
  -d subject_token="$SUBJ" -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience="$PMSS_ID" -d scope="read write" | jq -r .access_token)
jwt "$XCH" | jq '{aud, preferred_username, scope}'
```

K2F-6: run before the first browser sign-in of `alice`. K2F-7: run after K2F-1; the first call already fails.

### K2F-8 to K2F-10 – device code

```bash
DEV=$(curl -s "$KC/auth/device" -d client_id=pmss-cli -d scope="read write")
echo "$DEV" | jq '{user_code, verification_uri_complete, expires_in, interval}'
```

Open `verification_uri_complete` in the private window, sign in as `alice` (K2F-8, K2F-9) or `bob` (K2F-10) and confirm the consent page. Poll meanwhile:

```bash
DC=$(jq -r .device_code <<<"$DEV")
until R=$(curl -s "$KC/token" \
    -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
    -d client_id=pmss-cli -d device_code="$DC"); \
  jq -e .access_token <<<"$R" >/dev/null; do jq -c '{error}' <<<"$R"; sleep 5; done
TOK=$(jq -r .access_token <<<"$R"); jwt "$TOK" | jq '{aud, preferred_username, scope}'
```

For K2F-9 close the window at the OTP prompt and let the polling run until the code expires (then `Ctrl+C`). The token of K2F-8 can be used in the API tester or with `curl` against PMSS.

## 4. Evaluation

> **Expected outcome**
> - K2F-1 to K2F-5 and K2F-7 to K2F-10 pass → SEC-36 holds for browser sign-in, token exchange and device code.
> - K2F-6 is a property of the test realm, not of production: there no client has direct access grants, so no token without the browser flow exists. Check this in the production realm (config as code).
> - The tokens carry no `acr`/`amr` (the realm's own `basic` scope has no such mapper). PMSS does not check them anyway (design 7.5); the second factor is enforced by Keycloak alone.

A scripted run of these cases (browser sign-in with OTP setup, device code with consent, token exchange) against Keycloak 26.8.2 with this realm passed on 25.11.2026.
