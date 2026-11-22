# API mit curl ausprobieren

Die OpenAPI-Datei beschreibt die Endpoints und ihre Datenformate. Diese Beispiele zeigen zusätzlich den Ablauf mit Keycloak-Tokens und `ETag`-Headern. Sie sind für die lokale Integrationstest-Umgebung gedacht.

Für Linux gibt es ein ausführbares Bash-Skript, das eine Demo-Rolle erstellt, ihre ACLs mit `If-Match` ersetzt und sie beim Beenden wieder löscht:

```sh
cd test/integration
broker/make-certs.sh broker/run
docker compose up -d --build --wait
cd ../..
bash docs/curl-examples.sh
```

Benötigt werden `curl` und `jq`. Das Skript verwendet ausschließlich die Credentials des Test-Realm und verändert den lokalen Test-Broker. Es kann alternativ mit `BASE_URL` und `TOKEN_URL` auf andere Testinstanzen zeigen. Nicht gegen Produktion ausführen.

Die folgenden manuellen Beispiele sind für **PowerShell unter Windows**:

## Testumgebung und Tokens

Starte die lokale Umgebung wie in [test/integration](../test/integration/README.md) beschrieben. Die folgenden Schreibzugriffe verändern den Zustand des dortigen Test-Brokers; führe sie nicht gegen eine produktive Instanz aus.

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

Diese Credentials gehören ausschließlich zum Test-Realm. In Produktion werden Tokens über die dort konfigurierte Keycloak-Client-Konfiguration bezogen. `write` schließt `read` nicht ein; deshalb verwenden die Beispiele für `GET` den Read-Token und für Änderungen den Write-Token.

## Lesen

```powershell
curl.exe -i -H "Authorization: Bearer $ReadToken" "$BaseUrl/api/v1/info"
curl.exe -i -H "Authorization: Bearer $ReadToken" "$BaseUrl/api/v1/export"
```

`/info` liefert unter anderem die Namenspräfixe und Limits. `/export` zeigt den verwalteten Gesamtzustand. `-i` macht Status und Antwort-Header sichtbar; Fehlerantworten kommen als `application/problem+json`.

## Rolle erstellen, ändern und aufräumen

Der folgende Ablauf erstellt eine Testrolle mit einer ACL. Die Rolle wird anschließend mit einem aktuellen `ETag` geändert und wieder gelöscht. `PUT /acls` ersetzt dabei die **gesamte** ACL-Liste.

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

Ein vorhandenes Objekt muss bei Änderungen mit seinem aktuellen `ETag` geschützt werden: ohne `If-Match` antwortet der Dienst mit `428`, bei einem veralteten ETag mit `412`. Nach einem `504 broker_timeout` ist der Zustand unbekannt: erst erneut lesen, nicht blind denselben Schreibzugriff wiederholen. Tokens laufen nach kurzer Zeit ab; bei `401` die Token-Anforderung erneut ausführen.
