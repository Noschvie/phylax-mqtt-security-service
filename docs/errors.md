# Error codes

Every error response of the API is `application/problem+json` (RFC 9457) with `status`, `code` and `title`. Clients evaluate only `status` and `code`; `detail` is for display. The `type` URI points to the entry on this page.

The codes are those of the interface specification "MQTT Security Service API v1", section 3.5. Each code belongs to exactly one status. The last two entries are additions of this implementation.

| Status | Code | Meaning |
|---|---|---|
| 401 | <a id="invalid_token"></a>`invalid_token` | Token missing, invalid, expired, wrong `iss` or `aud`. `WWW-Authenticate` is set. |
| 403 | <a id="insufficient_scope"></a>`insufficient_scope` | Token lacks the scope (`read` for `GET`, `write` for changes). `WWW-Authenticate` is set. |
| 403 | <a id="not_managed"></a>`not_managed` | Object is not managed by the service (no prefix or marker). |
| 403 | <a id="reserved_name"></a>`reserved_name` | `pmss-*` or `role_security_manager`. |
| 404 | <a id="not_found"></a>`not_found` | Object or endpoint does not exist. |
| 409 | <a id="already_exists"></a>`already_exists` | An object with this name exists already. |
| 409 | <a id="certificate_client"></a>`certificate_client` | Password, `enable` or `disable` for a certificate client (`CN=…`). |
| 412 | <a id="precondition_failed"></a>`precondition_failed` | `If-Match` does not match the current ETag; nothing was changed. |
| 413 | <a id="payload_too_large"></a>`payload_too_large` | Request body larger than `limits.maxRequestBytes`. |
| 422 | <a id="validation_failed"></a>`validation_failed` | Invalid fields; `errors` holds JSON Pointers into the body. |
| 422 | <a id="unknown_role"></a>`unknown_role` | Role does not exist or is not managed. |
| 422 | <a id="unknown_group"></a>`unknown_group` | Group does not exist or is not managed. |
| 428 | <a id="precondition_required"></a>`precondition_required` | `If-Match` missing. |
| 500 | <a id="readback_mismatch"></a>`readback_mismatch` | The state read back after a change differs from the request. |
| 502 | <a id="broker_error"></a>`broker_error` | The broker reported an error or sent an unexpected answer. |
| 502 | <a id="partial_failure"></a>`partial_failure` | A compensation failed; an object exists half created. |
| 503 | <a id="broker_unavailable"></a>`broker_unavailable` | No connection to the broker; **nothing was sent**. Retrying later is safe. |
| 504 | <a id="broker_timeout"></a>`broker_timeout` | No answer in time; **the state is unknown**. Read the object again instead of retrying blindly. |
| 405 | <a id="method_not_allowed"></a>`method_not_allowed` | *Not in the specification.* The path exists, the method does not; `Allow` lists the methods. |
| 500 | <a id="internal_error"></a>`internal_error` | *Not in the specification.* Unexpected error in the service. |
