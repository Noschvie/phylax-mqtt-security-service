# Manual test: second factor for `security-admin` (authentik)

Manual test for SEC-36 with authentik: tokens with scope `write` only after a sign-in with a second factor, also for token exchange and the device authorization grant (design 7.5). Open question F-7 of the [authentik probe](README.md); it needs a browser and is not part of `check_tokens.py`.

> **What is tested**
> The token exchange itself is not interactive: authentik asks for no second factor during the exchange. The second factor has to apply at the **sign-in** the subject token comes from. The test therefore checks three things:
> 1. The browser sign-in (authorization code and device code) asks `security-admin` members for a second factor.
> 2. A token from such a sign-in can be exchanged for, or used with, `write`.
> 3. **No path without a second factor** leads to a token with `write`. Critical is the authentik app password (`client_credentials` with `username` and app password): it yields a user token without any browser sign-in. `check_tokens.py` already uses this path for `alice`.

## 1. Preparation

Start the probe as in the [README](README.md). The blueprint does not cover the following yet; set it up in the admin interface (`http://127.0.0.1:9180/if/admin/`):

- [ ] Authentication flow with an **Authenticator Validation Stage** (TOTP or WebAuthn), bound with a policy "user is member of group `security-admin`"; set as authentication flow of the brand.
- [ ] **Device code flow** set in the brand (without it authentik offers no device code sign-in).
- [ ] Provider `pmss`: grant type **Device code** added.
- [ ] `alice` (in `security-admin`) has TOTP enrolled; `bob` (no group) has not.

Already in the blueprint: users `alice`/`alice` and `bob`/`bob`, app password `alice-app-password`, redirect URI `http://127.0.0.1:8443/oidc/callback` of `tasmofleet-test` (the page does not have to exist; the code is in the address bar).

Use a private browser window, so that no existing session skips the second factor.

> **Note on PMSS**
> For the calls in the API tester, PMSS must accept authentik tokens: issuer `http://127.0.0.1:9180/application/o/pmss/`, audience `phylax-mqtt-security-service`, JWKS of provider `pmss`, and no `typ == "Bearer"` check (authentik sets no `typ` claim). As long as PMSS checks `typ`, every authentik token is rejected with `401`; the test then ends with the check of the token claims.

Variables:

```bash
AK=http://127.0.0.1:9180
TF_ID=tasmofleet-test;  TF_SECRET=tasmofleet-test-secret
PMSS_ID=phylax-mqtt-security-service;  PMSS_SECRET=pmss-test-secret
REDIRECT=http://127.0.0.1:8443/oidc/callback
```

Decode a token (payload):

```bash
jwt() { cut -d. -f2 <<<"$1" | tr '_-' '/+' | base64 -d 2>/dev/null; echo; }
```

## 2. Test cases

| No. | Steps | Expected | Result |
|---|---|---|---|
| F7-1 | Browser sign-in `alice` at `tasmofleet-test` (authorization code) | TOTP asked after the password; no code without TOTP | |
| F7-2 | Browser sign-in `bob` at `tasmofleet-test` | No second factor (policy applies to `security-admin` only) | |
| F7-3 | Exchange the token of F7-1 with `scope=read write`, then a `write` call in the API tester | Exchange `200`, `scope` = `read write`; PMSS call `2xx`. Record `amr` | |
| F7-4 | **Bypass:** token for `alice` via `client_credentials` with app password, then exchange with `write` | Required: no token with `write`. Likely actual: exchange succeeds → finding | |
| F7-5 | Device code `alice` at provider `pmss`, `scope=read write`, then a `write` call in the API tester | TOTP asked in the browser; token with `write`; PMSS call `2xx` | |
| F7-6 | Device code `alice`, cancel at the TOTP prompt | Polling stays `authorization_pending`, then `expired_token`; no token | |
| F7-7 | Device code `bob` with `scope=read write` | Refused (`access_denied`/`invalid_grant`, as with token exchange); with `scope=read` successful | |

## 3. Steps

### F7-1 / F7-2 – browser sign-in

Open in the private window:

```text
http://127.0.0.1:9180/application/o/authorize/?response_type=code&client_id=tasmofleet-test&redirect_uri=http://127.0.0.1:8443/oidc/callback&scope=openid%20profile%20email&state=f7
```

Sign in and watch for the TOTP prompt. Copy `code` from the address bar and redeem it at once (short lifetime):

```bash
CODE=<code>
SUBJ=$(curl -s "$AK/application/o/token/" \
  -d grant_type=authorization_code -d code="$CODE" -d redirect_uri="$REDIRECT" \
  -d client_id="$TF_ID" -d client_secret="$TF_SECRET" | jq -r .access_token)
jwt "$SUBJ" | jq '{sub, preferred_username, amr, acr, auth_time}'
```

Record: Was TOTP asked? What is in `amr` (expected for `alice` e.g. `["pwd","mfa"]` or `otp`, for `bob` only `["pwd"]`)?

### F7-3 – exchange after a sign-in with second factor

```bash
XCH=$(curl -s "$AK/application/o/token/" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id="$TF_ID" -d client_secret="$TF_SECRET" \
  -d subject_token="$SUBJ" -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience="$PMSS_ID" -d scope="read write" | jq -r .access_token)
jwt "$XCH" | jq '{iss, aud, sub, preferred_username, scope, amr}'
```

Use `$XCH` as bearer token in the API tester for a harmless `write` call, e.g. create client `tf_f7-probe` and delete it again. Record: Is `amr` carried over into the exchanged token?

### F7-4 – bypass with app password

```bash
APW=$(curl -s "$AK/application/o/token/" \
  -d grant_type=client_credentials -d client_id="$TF_ID" -d client_secret="$TF_SECRET" \
  -d username=alice -d password=alice-app-password -d scope="openid profile" | jq -r .access_token)
jwt "$APW" | jq '{sub, preferred_username, amr}'
```

Then the same exchange as in F7-3 with `subject_token="$APW"`. A token with `write` means the second factor is bypassed.

### F7-5 to F7-7 – device code

```bash
DEV=$(curl -s "$AK/application/o/device/" -d client_id="$PMSS_ID" -d client_secret="$PMSS_SECRET" -d scope="read write")
echo "$DEV" | jq '{user_code, verification_uri_complete, expires_in, interval}'
```

Open `verification_uri_complete` in the private window and sign in as `alice` (F7-5, F7-6) or `bob` (F7-7). Poll meanwhile:

```bash
DC=$(jq -r .device_code <<<"$DEV")
until R=$(curl -s "$AK/application/o/token/" \
    -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
    -d device_code="$DC" -d client_id="$PMSS_ID" -d client_secret="$PMSS_SECRET"); \
  jq -e .access_token <<<"$R" >/dev/null; do jq -c '{error}' <<<"$R"; sleep 5; done
TOK=$(jq -r .access_token <<<"$R"); jwt "$TOK" | jq '{aud, sub, scope, amr}'
```

For F7-6 close the TOTP page and let the polling run until the code expires (then `Ctrl+C`). For F7-5 use `$TOK` in the API tester as in F7-3.

## 4. Evaluation

> **Possible outcomes**
> - F7-1 and F7-5 pass and F7-4 is refused → SEC-36 holds for authentik without further measures.
> - **F7-4 succeeds** → finding. Candidate measures:
>   - Expression policy on application `pmss`: `write` only if the subject token comes from a sign-in with a second factor (`amr` contains `mfa`/`otp`). Requires `amr` in the subject token or in the policy context (F7-3).
>   - No app passwords for members of `security-admin` (policy on application `tasmofleet-test`).
>   - PMSS checks `amr` itself – contradicts design 7.5 ("the service does not check `acr`/`amr`"), so only as a last resort.
