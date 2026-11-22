# OpenAPI check

[`api/openapi.yaml`](../../api/openapi.yaml) is the machine-readable form of the specification "MQTT Security Service API v1" (draft v0.8). **The Markdown specification is normative**; a contradiction between the two is an error in the OpenAPI file. Additions of PMSS that are not in the specification carry the tag `pmss-extra` and `x-pmss-extra: true`.

[`check.py`](check.py) keeps the document honest:

1. It is valid OpenAPI 3.1.
2. Its operations are exactly the routes in `internal/api/api.go`; `x-pmss-extra` and the tag `pmss-extra` agree.
3. Every HTTP response that the Go tests recorded matches the document: status, required headers (`ETag`, `Location`, `WWW-Authenticate`), body schema and the error codes per status. `--require-all` fails if an operation was never recorded.

Responses are recorded by [`internal/testrecord`](../../internal/testrecord/testrecord.go) when `PMSS_TEST_RECORD_DIR` is set: by the unit tests (fake broker), by the integration tests against Mosquitto and by the end-to-end tests against the running service.

```sh
python3 -m venv .venv && .venv/bin/pip install -r test/openapi/requirements.txt
PMSS_TEST_RECORD_DIR=/tmp/records go test ./...
.venv/bin/python test/openapi/check.py --records /tmp/records --require-all
```

CI runs it after the unit tests (`ci.yml`) and after the integration tests (`integration.yml`).

Two problems are allowed on every operation without being listed there: `413 payload_too_large` (the body limit applies to every request) and `500 internal_error` (addition of PMSS).
