# Try the API with curl

The OpenAPI file describes the endpoints and their data formats. These examples also demonstrate the workflow with Keycloak tokens and `ETag` headers. They are intended for the local integration test environment.

For Linux, an executable Bash script creates a demo role, replaces its ACLs with `If-Match`, and deletes it on completion:

```sh
cd test/integration
broker/make-certs.sh broker/run
docker compose up -d --build --wait
cd ../..
bash docs/curl-examples.sh
```

The script requires `curl` and `jq`. It uses only the credentials of the test realm and modifies the local test broker. You can also point it to other test instances with `BASE_URL` and `TOKEN_URL`. Do not run it against production.

The following manual examples are for **PowerShell on Windows**:

## Test environment and tokens

Start the local environment as described in [test/integration](../test/integration/README.md). The write operations below modify the state of the test broker; do not run them against a production instance.

```powershell
$BaseUrl = 'http://127.0.0.1:18080'
$TokenUrl = 'http://127.0.0.1:8180/realms/pmss-test/protocol/openid-connect/token'

$ReadToken = (curl.exe -fsS $TokenUrl `
  -d 'grant_type=client_credentials' `
  -d 'client_id=msm-test-ro' `
  -d 'client_secret=msm-test-ro-secret' | ConvertFrom-Json).access_token

$WriteToken = (curl.exe -fsS $TokenUrl `
  -d 'grant_type=client_credentials' `
  -d 'client_id=msm-test-rw' `
  -d 'client_secret=msm-test-rw-secret' | ConvertFrom-Json).access_token
```

These credentials belong exclusively to the test realm. In production, obtain tokens through the configured Keycloak client configuration. `write` does not include `read`; therefore, the examples use the read token for `GET` requests and the write token for changes.

## Read

```powershell
curl.exe -i -H "Authorization: Bearer $ReadToken" "$BaseUrl/api/v1/info"
curl.exe -i -H "Authorization: Bearer $ReadToken" "$BaseUrl/api/v1/export"
```

`/info` provides, among other information, name prefixes and limits. `/export` shows the complete managed state. `-i` makes the status and response headers visible; error responses use `application/problem+json`.

## Create, update, and clean up a role

The following workflow creates a test role with one ACL. It then updates the role using a current `ETag` and deletes it. `PUT /acls` replaces the **entire** ACL list.

```powershell
# Create the role; the response also contains the ETag header.
curl.exe -i -X POST "$BaseUrl/api/v1/roles" `
  -H "Authorization: Bearer $WriteToken" `
  -H 'Content-Type: application/json' `
  --data-raw '{"rolename":"tf_curl_demo","textname":"curl demo","acls":[{"acltype":"publishClientSend","topic":"curl-demo/#","allow":true}]}'

# Get the current ETag from the response headers.
$RoleHeaders = curl.exe -sS -D - -o NUL `
  -H "Authorization: Bearer $ReadToken" `
  "$BaseUrl/api/v1/roles/tf_curl_demo"
$RoleETag = ($RoleHeaders | Where-Object { $_ -match '^ETag:' } | Select-Object -First 1) -replace '^ETag:\s*', ''

# Replace the ACL list. The ETag must be passed exactly, including quotes.
$RoleHeaders = curl.exe -sS -D - -o NUL -X PUT `
  -H "Authorization: Bearer $WriteToken" `
  -H "If-Match: $RoleETag" `
  -H 'Content-Type: application/json' `
  --data-raw '{"acls":[{"acltype":"publishClientSend","topic":"curl-demo/#","allow":true},{"acltype":"subscribeLiteral","topic":"curl-demo/status","allow":true}]}' `
  "$BaseUrl/api/v1/roles/tf_curl_demo"
$RoleETag = ($RoleHeaders | Where-Object { $_ -match '^ETag:' } | Select-Object -First 1) -replace '^ETag:\s*', ''

# Clean up using the ETag that is current after the update.
curl.exe -i -X DELETE "$BaseUrl/api/v1/roles/tf_curl_demo" `
  -H "Authorization: Bearer $WriteToken" `
  -H "If-Match: $RoleETag"
```

An existing object must be protected by its current `ETag` when it is modified: without `If-Match`, the service responds with `428`; with an outdated ETag, it responds with `412`. After a `504 broker_timeout`, the state is unknown: read the object again instead of blindly repeating the same write operation. Tokens expire after a short time; on `401`, repeat the token request.
