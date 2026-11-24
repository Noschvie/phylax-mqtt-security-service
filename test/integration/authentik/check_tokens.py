#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identity provider probe: the Keycloak token checks against authentik.

Counterpart of test/integration/keycloak/check_tokens.py. Checks what
authentik puts into the tokens: scopes read/write, audience, write only
for security-admin, token exchange for TasmoFleet (RFC 8693). Lines with
INFO record behaviour that PMSS and the specification have to take into
account; they do not fail the run. Python standard library only.

Runs against authentik started with blueprints/pmss-test.yaml
(see compose.yaml):
  python3 check_tokens.py [base-url]      default http://127.0.0.1:9180
Exit code 0 if all checks pass.
"""

import base64
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9180").rstrip("/")
TOKEN_URL = f"{BASE}/application/o/token/"
PMSS_ROOT = f"{BASE}/application/o/pmss/"
AUD = "phylax-mqtt-security-service"
TF = ("tasmofleet-test", "tasmofleet-test-secret")
TE = "urn:ietf:params:oauth:grant-type:token-exchange"
AT = "urn:ietf:params:oauth:token-type:access_token"

failed = 0


def request(url, data=None, host=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    if host:
        req.add_header("Host", host)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
        return 0, {"error": str(e)}


def post(data, host=None):
    return request(TOKEN_URL, data, host)


def part(token, i):
    p = token.split(".")[i]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def claims(token):
    return part(token, 1)


def header(token):
    return part(token, 0)


def aud_list(c):
    a = c.get("aud", [])
    return [a] if isinstance(a, str) else a


def scopes(c):
    s = c.get("scope", "")
    return set(s.split()) if isinstance(s, str) else set(s)


def summary(c):
    return (f"scope='{c.get('scope', '')}' aud={aud_list(c)} sub={'yes' if c.get('sub') else 'NO'} "
            f"user={c.get('preferred_username')} azp={c.get('azp')} iss={c.get('iss')}")


def check(name, ok, detail):
    global failed
    print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}")
    if not ok:
        failed = 1


def info(name, detail):
    print(f"INFO  {name}\n      {detail}")


def result(st, r):
    c = claims(r["access_token"]) if st == 200 and "access_token" in r else {}
    return c, (f"HTTP {st}: " + (summary(c) if c else json.dumps(r)))


# authentik form of the password grant: client_credentials with username and
# app password (blueprint: app passwords alice-app-password, msm-test-rw-secret …)
def user_token(user, scope="openid profile"):
    return post({"grant_type": "client_credentials", "client_id": TF[0],
                 "username": user, "password": f"{user}-app-password", "scope": scope})


def service_token(user, scope="read write", client_id=AUD, host=None):
    return post({"grant_type": "client_credentials", "client_id": client_id,
                 "username": user, "password": f"{user}-secret", "scope": scope}, host)


def exchange(subject_token, scope="read write", audience=AUD):
    data = {"grant_type": TE, "client_id": TF[0], "client_secret": TF[1],
            "subject_token": subject_token, "subject_token_type": AT,
            "requested_token_type": AT, "scope": scope}
    if audience:
        data["audience"] = audience
    return post(data)


# --- wait until authentik is up and the blueprint is applied -----------------
deadline = time.time() + 600
while True:
    st, r = service_token("msm-test-rw")
    if st == 200:
        break
    if time.time() > deadline:
        print(f"authentik not ready or blueprint not applied: HTTP {st} {r}", file=sys.stderr)
        sys.exit(2)
    time.sleep(5)

# --- discovery, signing --------------------------------------------------------
st, disc = request(PMSS_ROOT + ".well-known/openid-configuration")
st_j, jwks = request(disc.get("jwks_uri", PMSS_ROOT + "jwks/")) if st == 200 else (0, {})
kids = {k.get("kid") for k in jwks.get("keys", [])}
info("discovery of the pmss provider",
     f"issuer={disc.get('issuer')} jwks_uri={disc.get('jwks_uri')} "
     f"grant_types={disc.get('grant_types_supported')}")

st, r = service_token("msm-test-rw")
tok = r["access_token"]
c, h = claims(tok), header(tok)
check("access token signed with RS256, kid in the JWKS of the pmss provider",
      h.get("alg") == "RS256" and h.get("kid") in kids, f"header={h} kids={sorted(kids)}")
check("iss of the token = issuer of the discovery document",
      c.get("iss") == disc.get("issuer"), f"iss={c.get('iss')} discovery={disc.get('issuer')}")

# F-2, F-3: how to tell an access token from an ID token (PMSS checks typ == "Bearer")
info("F-2 typ of the access token",
     f"header typ={h.get('typ')!r}, claim typ={c.get('typ')!r} (Keycloak: claim typ='Bearer')")
info("F-3 scope claim of the access token",
     f"type={type(c.get('scope')).__name__} value={c.get('scope')!r}; claims={sorted(c)}")

# T-8: authentik builds the issuer from the Host of the request
st, r = service_token("msm-test-rw", host="authentik-server:9000")
ci = claims(r["access_token"]) if st == 200 else {}
info("T-8 issuer with another host name (Host: authentik-server:9000)",
     f"iss={ci.get('iss')} – same as above: {ci.get('iss') == c.get('iss')}")

# --- service accounts (client credentials) ----------------------------------------
st, r = service_token("msm-test-rw")
c, d = result(st, r)
check("msm-test-rw: read and write, aud = Security Service",
      st == 200 and {"read", "write"} <= scopes(c) and AUD in aud_list(c), d)

st, r = service_token("msm-test-ro", scope="read")
c, d = result(st, r)
check("msm-test-ro: read only", st == 200 and "read" in scopes(c) and "write" not in scopes(c), d)

st, r = service_token("msm-test-ro", scope="read write")
c, d = result(st, r)
check("msm-test-ro asks for write: not granted", "write" not in scopes(c), d)
info("F-1 answer of authentik to write without security-admin", d)

st, r = service_token("msm-test-rw-norole", scope="read write")
c, d = result(st, r)
check("service account WITHOUT security-admin asks for write: no write", "write" not in scopes(c), d)

# --- user tokens of TasmoFleet ------------------------------------------------------
st, r = user_token("alice")
alice = r.get("access_token")
c, d = result(st, r)
check("original TasmoFleet token (alice): aud does not contain the Security Service",
      bool(alice) and AUD not in aud_list(c), d)
if r.get("id_token"):
    idc, idh = claims(r["id_token"]), header(r["id_token"])
    info("F-2 ID token of TasmoFleet (for comparison)",
         f"header typ={idh.get('typ')!r} claim typ={idc.get('typ')!r} scope={idc.get('scope')!r} "
         f"aud={aud_list(idc)} claims={sorted(idc)}")

st, r = user_token("bob")
bob = r.get("access_token")
check("original TasmoFleet token (bob)", bool(bob), f"HTTP {st}")

alice_other_st, alice_other = post({"grant_type": "client_credentials", "client_id": "other-app",
                                    "username": "alice", "password": "alice-app-password",
                                    "scope": "openid profile"})

# --- token exchange (RFC 8693) -------------------------------------------------------
st, r = exchange(alice)
c, d = result(st, r)
check("token exchange alice (security-admin): aud = Security Service, read+write, user = alice",
      st == 200 and aud_list(c) == [AUD] and {"read", "write"} <= scopes(c)
      and c.get("preferred_username") == "alice" and bool(c.get("sub")), d)
if c:
    info("F-4 claims of the exchanged token",
         f"azp={c.get('azp')!r} (Keycloak: tasmofleet-test) act={c.get('act')!r} claims={sorted(c)}")
    info("F-5 issuer of the exchanged token", f"iss={c.get('iss')} (expected: {disc.get('issuer')})")

st, r = exchange(bob)
c, d = result(st, r)
check("token exchange bob (no security-admin), read write: no write",
      "write" not in scopes(c), d)
info("F-1 token exchange without security-admin (Keycloak: 200 with scope=read)", d)

st, r = exchange(bob, scope="read")
c, d = result(st, r)
check("token exchange bob, scope read only: read, aud = Security Service, user = bob",
      st == 200 and "read" in scopes(c) and AUD in aud_list(c) and c.get("preferred_username") == "bob", d)

st, r = exchange(alice, audience="other-app")
check("token exchange to a provider that does not trust TasmoFleet: refused",
      st >= 400, f"HTTP {st}: {r}")

st, r = service_token("msm-test-rw")
st, r = exchange(r["access_token"])
check("token exchange of a token issued to the Security Service (msm-test-rw): refused",
      st >= 400, f"HTTP {st}: {r}")

if alice_other_st == 200:
    st, r = exchange(alice_other["access_token"])
    check("token exchange of a token issued to another application (other-app): refused",
          st >= 400, f"HTTP {st}: {r}")
else:
    check("token of other-app for alice", False, f"HTTP {alice_other_st}: {alice_other}")

st, r = exchange(alice, audience=None)
c, d = result(st, r)
info("token exchange without audience (token for TasmoFleet itself)", d)

sys.exit(failed)
