#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check the Keycloak part of the integration tests (PMSS design, section 7.9).

Checks what Keycloak puts into the tokens: scopes read/write, audience,
the role mapping of scope 'write' to security-admin and Standard Token
Exchange for TasmoFleet. Python standard library only.

Runs against a Keycloak started with the test realm 'pmss-test'
(see compose.yaml):
  python3 check_tokens.py [base-url]      default http://127.0.0.1:8180
Exit code 0 if all checks pass.
"""

import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8180"
TOKEN_URL = f"{BASE}/realms/pmss-test/protocol/openid-connect/token"
AUD = "phylax-mqtt-security-service"
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"

failed = 0


def post(data, basic=None):
    req = urllib.request.Request(TOKEN_URL, data=urllib.parse.urlencode(data).encode())
    if basic:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode())
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def aud_list(c):
    a = c.get("aud", [])
    return [a] if isinstance(a, str) else a


def summary(c):
    return (f"scope='{c.get('scope', '')}' aud={aud_list(c)} sub={'yes' if c.get('sub') else 'NO'} "
            f"user={c.get('preferred_username')} azp={c.get('azp')}")


def check(name, ok, detail):
    global failed
    print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}")
    if not ok:
        failed = 1


def scopes(c):
    return set(c.get("scope", "").split())


def client_credentials(cid, secret, scope=None):
    data = {"grant_type": "client_credentials"}
    if scope:
        data["scope"] = scope
    return post(data, (cid, secret))


def user_token(user, scope=None):
    data = {"grant_type": "password", "username": user, "password": user}
    if scope:
        data["scope"] = scope
    return post(data, ("tasmofleet-test", "tasmofleet-test-secret"))


def exchange(subject_token, scope="read write", audience=AUD):
    data = {"grant_type": TE, "subject_token": subject_token, "subject_token_type": AT,
            "requested_token_type": AT, "audience": audience, "scope": scope}
    return post(data, ("tasmofleet-test", "tasmofleet-test-secret"))


# --- Client Credentials -------------------------------------------------
st, r = client_credentials("msm-test-rw", "msm-test-rw-secret")
c = claims(r["access_token"]) if st == 200 else {}
check("msm-test-rw: read and write, aud = Security Service",
      st == 200 and {"read", "write"} <= scopes(c) and AUD in aud_list(c), summary(c) if c else r)

st, r = client_credentials("msm-test-ro", "msm-test-ro-secret")
c = claims(r["access_token"]) if st == 200 else {}
check("msm-test-ro: read only", st == 200 and "read" in scopes(c) and "write" not in scopes(c), summary(c) if c else r)

st, r = client_credentials("msm-test-ro", "msm-test-ro-secret", scope="write")
c = claims(r["access_token"]) if st == 200 else {}
check("msm-test-ro asks for write: not granted",
      "write" not in scopes(c), f"HTTP {st}: " + (summary(c) if c else str(r)))

st, r = client_credentials("msm-test-rw-norole", "msm-test-rw-norole-secret")
c = claims(r["access_token"]) if st == 200 else {}
check("service account with write as default scope but WITHOUT security-admin: no write",
      st == 200 and "write" not in scopes(c), summary(c) if c else r)

# --- User tokens of TasmoFleet ------------------------------------------
st, r = user_token("alice")
alice = r.get("access_token")
c = claims(alice) if alice else {}
check("original TasmoFleet token (alice): aud does not contain the Security Service",
      bool(alice) and AUD not in aud_list(c), summary(c) if c else r)

st, r = user_token("bob")
bob = r.get("access_token")

# --- Standard Token Exchange --------------------------------------------
st, r = exchange(alice)
c = claims(r["access_token"]) if st == 200 else {}
check("token exchange alice (security-admin): aud = Security Service, read+write, sub = alice",
      st == 200 and aud_list(c) == [AUD] and {"read", "write"} <= scopes(c) and c.get("preferred_username") == "alice"
      and bool(c.get("sub")),
      f"HTTP {st}: " + (summary(c) if c else str(r)))

st, r = exchange(bob)
c = claims(r["access_token"]) if st == 200 else {}
check("token exchange bob (no security-admin): no write",
      (st == 200 and "write" not in scopes(c)) or st >= 400,
      f"HTTP {st}: " + (summary(c) if c else str(r)))

st, r = exchange(bob, scope="read")
c = claims(r["access_token"]) if st == 200 else {}
check("token exchange bob, scope read only: read, aud = Security Service, sub = bob",
      st == 200 and "read" in scopes(c) and AUD in aud_list(c) and c.get("preferred_username") == "bob",
      f"HTTP {st}: " + (summary(c) if c else str(r)))

st, r = exchange(alice, audience="msm-test-rw")
check("token exchange to an audience that no scope provides: refused",
      st >= 400, f"HTTP {st}: {r}")

# A token issued to another client must not be exchangeable by TasmoFleet
st, r = client_credentials("msm-test-rw", "msm-test-rw-secret")
st, r = exchange(r["access_token"])
check("token exchange of a token issued to another client (msm-test-rw): refused",
      st >= 400, f"HTTP {st}: {r}")

sys.exit(failed)
