#!/usr/bin/env bash
set -euo pipefail

# Demo against the local integration environment only. See docs/curl-examples.md.
BASE_URL="${BASE_URL:-http://127.0.0.1:18080}"
TOKEN_URL="${TOKEN_URL:-http://127.0.0.1:8180/realms/pmss-test/protocol/openid-connect/token}"
ROLE="tf_curl_demo_$(date +%s)_$$"
TOPIC="curl-demo/$ROLE/#"
created=0

for command in curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

printf 'Waiting for PMSS at %s\n' "$BASE_URL"
for _ in $(seq 1 30); do
  if curl --noproxy '*' --fail --silent --show-error "$BASE_URL/healthz" >/dev/null; then
    break
  fi
  sleep 1
done
if ! curl --noproxy '*' --fail --silent --show-error "$BASE_URL/healthz" >/dev/null; then
  printf 'PMSS is not reachable at %s\n' "$BASE_URL" >&2
  exit 1
fi

read_token="$(
  curl --noproxy '*' --fail-with-body --silent --show-error "$TOKEN_URL" \
    --data 'grant_type=client_credentials' \
    --data 'client_id=msm-test-ro' \
    --data 'client_secret=msm-test-ro-secret' |
    jq -er '.access_token'
)"
write_token="$(
  curl --noproxy '*' --fail-with-body --silent --show-error "$TOKEN_URL" \
    --data 'grant_type=client_credentials' \
    --data 'client_id=msm-test-rw' \
    --data 'client_secret=msm-test-rw-secret' |
    jq -er '.access_token'
)"

get_role_etag() {
  curl --noproxy '*' --fail-with-body --silent --show-error --dump-header - --output /dev/null \
    --header "Authorization: Bearer $read_token" \
    "$BASE_URL/api/v1/roles/$ROLE" |
    awk 'tolower($1) == "etag:" { sub(/\r$/, "", $2); print $2; exit }'
}

cleanup() {
  if [[ "$created" == 1 ]]; then
    local etag
    if etag="$(get_role_etag)" && [[ -n "$etag" ]]; then
      curl --noproxy '*' --fail-with-body --silent --show-error --include --request DELETE \
        --header "Authorization: Bearer $write_token" \
        --header "If-Match: $etag" \
        "$BASE_URL/api/v1/roles/$ROLE" || {
          printf 'Could not clean up demo role %s\n' "$ROLE" >&2
          return 1
        }
      printf 'Deleted demo role %s\n' "$ROLE"
    else
      printf 'Could not read ETag to clean up demo role %s\n' "$ROLE" >&2
      return 1
    fi
  fi
}
trap cleanup EXIT

printf 'GET /api/v1/info\n'
curl --noproxy '*' --fail-with-body --silent --show-error --include \
  --header "Authorization: Bearer $read_token" \
  "$BASE_URL/api/v1/info"

printf '\nPOST /api/v1/roles (%s)\n' "$ROLE"
create_body="$(jq -n --arg role "$ROLE" --arg topic "$TOPIC" \
  '{rolename:$role, textname:"curl demo", acls:[{acltype:"publishClientSend",topic:$topic,allow:true}]}')"
curl --noproxy '*' --fail-with-body --silent --show-error --include --request POST \
  --header "Authorization: Bearer $write_token" \
  --header 'Content-Type: application/json' \
  --data "$create_body" \
  "$BASE_URL/api/v1/roles"
created=1

etag="$(get_role_etag)"
if [[ -z "$etag" ]]; then
  printf 'No ETag returned for role %s\n' "$ROLE" >&2
  exit 1
fi

printf '\nPUT /api/v1/roles/%s/acls (If-Match: %s)\n' "$ROLE" "$etag"
replace_body="$(jq -n --arg topic "$TOPIC" \
  '{acls:[{acltype:"publishClientSend",topic:$topic,allow:true},{acltype:"subscribeLiteral",topic:"curl-demo/status",allow:true}]}')"
curl --noproxy '*' --fail-with-body --silent --show-error --include --request PUT \
  --header "Authorization: Bearer $write_token" \
  --header "If-Match: $etag" \
  --header 'Content-Type: application/json' \
  --data "$replace_body" \
  "$BASE_URL/api/v1/roles/$ROLE/acls"

printf '\nThe EXIT trap removes the demo role with its current ETag.\n'
