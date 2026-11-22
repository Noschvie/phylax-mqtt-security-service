#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check api/openapi.yaml against the service.

1. The document is valid OpenAPI 3.2.
2. The operations match the routes registered in internal/api/api.go, and
   every addition of PMSS carries the tag "pmss-extra" and x-pmss-extra.
3. Every response recorded by the Go tests (PMSS_TEST_RECORD_DIR, see
   internal/testrecord) matches the document: status, headers, body.

Usage: check.py [--records DIR] [--require-all]
  --require-all  fail if an operation of the document was never recorded
"""

import argparse
import glob
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml
from openapi_core import Config, OpenAPI
from openapi_core.testing import MockRequest, MockResponse
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "api" / "openapi.yaml"
ROUTES = ROOT / "internal" / "api" / "api.go"
METHODS = {"get", "put", "post", "delete", "patch"}
HOST = "https://pmss.example.org"
# Problems that every operation can return; the document lists them only
# where a body is expected (413) or not at all (internal_error).
ANYWHERE = {(413, "payload_too_large"), (500, "internal_error")}

failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL ", msg)


def operations(doc):
    ops = {}
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if method in METHODS:
                ops[(method.upper(), path)] = op
    return ops


def check_routes(ops):
    src = ROUTES.read_text()
    routes = set(re.findall(r'(?:read|write|HandleFunc)\("([A-Z]+) (/[^"]*)"', src))
    spec = set(ops)
    for r in sorted(routes - spec):
        fail(f"route {r[0]} {r[1]} is not in the OpenAPI document")
    for r in sorted(spec - routes):
        fail(f"operation {r[0]} {r[1]} has no route in internal/api/api.go")
    for (m, p), op in sorted(ops.items()):
        extra = op.get("x-pmss-extra", False)
        tagged = "pmss-extra" in op.get("tags", [])
        if extra != tagged:
            fail(f"{m} {p}: x-pmss-extra and tag pmss-extra disagree")
    print(f"routes: {len(routes)}, operations: {len(spec)}, "
          f"specification: {sum(1 for o in ops.values() if not o.get('x-pmss-extra'))}, "
          f"pmss-extra: {sum(1 for o in ops.values() if o.get('x-pmss-extra'))}")


def template_of(ops, method, path):
    """Path template of the document for a concrete path."""
    for m, tpl in ops:
        if m != method:
            continue
        rx = "^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(tpl)) + "$"
        if re.match(rx, path):
            return tpl
    return None


def check_records(openapi, ops, directory, require_all):
    files = sorted(glob.glob(str(Path(directory) / "*.jsonl")))
    if not files:
        fail(f"no records in {directory}")
        return
    seen = Counter()
    total = 0
    for f in files:
        for line in open(f, encoding="utf-8"):
            ex = json.loads(line)
            total += 1
            method, path, status = ex["method"], ex["path"], ex["status"]
            headers = ex["headers"]
            ctype = headers.get("Content-Type", "")
            tpl = template_of(ops, method, path)
            if tpl is None:
                # Unknown path or method: 404/405 problem+json from the router.
                if status in (404, 405) and ctype.startswith("application/problem+json"):
                    continue
                fail(f"{method} {path} → {status}: no operation in the document")
                continue
            code = json.loads(ex["body"] or "{}").get("code") if ctype.startswith("application/problem+json") else None
            if (status, code) in ANYWHERE:
                seen[(method, tpl, status)] += 1
                continue  # possible on every operation, not listed per operation
            req = MockRequest(HOST, method.lower(), path, path_pattern=tpl)
            resp = MockResponse(ex["body"].encode(), status_code=status, headers=headers,
                                content_type=ctype.split(";")[0] if ctype else None)
            try:
                openapi.validate_response(req, resp)
            except Exception as e:  # noqa: BLE001 – report every kind of mismatch
                detail = getattr(e, "__cause__", None) or e
                fail(f"{method} {path} → {status}: {type(e).__name__}: {detail}\n      body: {ex['body'][:300]}")
                continue
            seen[(method, tpl, status)] += 1
    print(f"records: {total} from {len(files)} files")
    covered = {(m, t) for m, t, _ in seen}
    missing = sorted(set(ops) - covered)
    for m, t in missing:
        msg = f"operation {m} {t} never recorded"
        if require_all:
            fail(msg)
        else:
            print("note ", msg)
    print(f"operations covered: {len(covered)}/{len(ops)}, "
          f"distinct (operation, status): {len(seen)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records")
    ap.add_argument("--require-all", action="store_true")
    args = ap.parse_args()

    doc = yaml.safe_load(SPEC.read_text())
    validate(doc)
    print(f"{SPEC.relative_to(ROOT)}: valid OpenAPI {doc['openapi']}")
    ops = operations(doc)
    check_routes(ops)
    if args.records:
        config = Config(extra_media_type_deserializers={"application/problem+json": json.loads})
        check_records(OpenAPI.from_dict(doc, config=config), ops, args.records, args.require_all)
    if failures:
        print(f"\n{len(failures)} failure(s)")
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    main()
