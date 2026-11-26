# MQTT Security Management – TasmoFleet und PMSS
## Architektur-Überblick – Draft for Review

**Status:** Draft – zur technischen Durchsicht  
**Version:** 1.1  
**Datum:** 25. November 2026  
**Detaildokument:** `phylax-mqtt-security-service-design` (aktuelle Fassung)  
**Schnittstellenspezifikation:** `mqtt-security-service-api-v1` („MQTT Security Service API v1“, aktuelle Fassung)  
**Identity Provider:** OIDC-Provider mit Token Exchange; getestet mit Keycloak 26.8.2 und authentik 2026.8.6, mindestens Keycloak 26.2 bzw. authentik 2026.8.3

> **Hinweis zu Namen und Umgebung**
> Das Dokument beschreibt die Architektur allgemein. Namen von Hosts, Benutzern und Domains sind Platzhalter: `legacy-shared-user` für den gemeinsamen Bestandsbenutzer, `mqtt.example.org` für den Broker-Namen der TLS-Listener. Die Angaben zur konkreten Umgebung (Hosts, Pfade, Netze, Inventar, Migrationsstand) stehen in einem getrennten, nicht öffentlichen Betriebsdokument.

---

> **Testergebnisse vom 20. November 2026**
> Geprüft mit `mqtt-acl-verify` gegen **Mosquitto 2.1.2** mit Dynamic Security (Test-Broker `testbroker-dynsec/`, CI auf amd64 und arm64 sowie Mosquitto 2.1.2 aus dem Quellcode). Einzelheiten im PMSS-Dokument und in `docs/testbroker-dynsec.md`.
> 1. **Rechte wie Classic ACL:** Die bisherigen 11 Fälle bestehen auch mit DynSec, inklusive Deny für FILEDOWNLOAD per Priorität. ✅
> 2. **`dynsec init` gibt dem Admin Lesezugriff auf `#`.** Die Rolle `admin` wird deshalb durch `role_security_manager` ersetzt und gelöscht.
> 3. **Deny-by-default muss explizit gesetzt werden:** `publishClientReceive` ist nach `init` erlaubt.
> 4. **Platzhalter `%u`/`%c` in DynSec erst ab 2.1.**
> 5. **Admin nur per Zertifikat (`use_identity_as_username`):** Der Admin wird an allen anderen Listenern abgelehnt. Mit Passwort wäre er auch an 1883 zugelassen.
> 6. **`disableClient` sperrt keine Zertifikatsanmeldung:** Der Client behält seine Rechte. Gesperrt wird mit `deleteClient`.
> 7. **App-Zertifikate mit `use_subject_as_username`:** Ein App-Zertifikat mit `CN=pmss-admin` wird zu `CN=pmss-admin,O=mqtt-apps` und erhält keine Admin-Rechte.
> 8. **Ein Listener kann Zertifikat und Passwort nicht mischen:** getrennte Listener nötig.
> 9. **Passwort-Hashes lassen sich übernehmen:** DynSec speichert dasselbe `$7$`-Format wie `pwfile`. Das bisherige Passwort bleibt gültig.
> 10. **`mosquitto_ctrl` endet auch bei „Not authorized“ mit Exit-Code 0.** Skripte prüfen die Ausgabe.

> **Testergebnisse der Identity Provider (21. und 24. November 2026)**
> Geprüft wird, was der Provider in die Tokens schreibt; PMSS ist dabei noch nicht beteiligt. Einzelheiten im PMSS-Dokument, Abschnitt 7.9.
> - **Keycloak 26.8.2** (`test/integration/keycloak`, 10 von 10): `write` nur für `security-admin`, Token Exchange mit `aud` = PMSS und `sub` = Benutzer, fremde Tokens nicht tauschbar. ✅
> - **authentik 2026.8.6** (`test/integration/authentik`, 16 von 16): dieselben Eigenschaften. ✅ Abweichend: `write` ohne `security-admin` lehnt die ganze Anfrage ab, kein `typ`-Claim, `azp` ist PMSS, der Issuer folgt dem Hostnamen der Anfrage.

> **Übernommen aus v0.2 (19. November 2026)**
> Mosquitto Classic ACL kennt Deny-Regeln (`topic deny <topic>`), mit Vorrang vor read/write. Relevant für den Ausgangszustand vor der Migration.

---

## 1. Ziel

Die bisherige Mosquitto-Verwaltung über `password_file` und optional `acl_file` wird schrittweise durch das integrierte Mosquitto Dynamic Security Plugin (DynSec) abgelöst.

Die Benutzer- und Rechteverwaltung erfolgt zunächst direkt mit `mosquitto_ctrl`. Danach übernimmt sie der **Phylax MQTT Security Service (PMSS)**, eine Go-Anwendung mit REST-API, die intern über MQTT mit dem Broker spricht.

**TasmoFleet** erhält einen Security Manager, mit dem Administratoren MQTT-Clients, Profile und Zugangsdaten verwalten. TasmoFleet setzt diese Änderungen nicht selbst am Broker um, sondern über die REST-API von PMSS.

Ausgangslage: Ein gemeinsamer MQTT-Benutzer (im Dokument `legacy-shared-user`) wird von mehreren Tasmota-Geräten und Anwendungen verwendet. Ein Client kann deshalb Topics anderer Clients lesen oder beschreiben. Besonders schützenswert sind Konfigurationsdaten, Zugangsdaten sowie Backup- und Restore-Inhalte.

**Grundsätze:**

- Der Broker bleibt eine eigenständige Infrastrukturkomponente.
- TasmoFleet verwaltet, betreibt aber weder Broker noch DynSec-Admin.
- Deny-by-default: Was in keinem Profil und keiner Ausnahme erlaubt ist, ist verboten.
- Die erste Migration bleibt bewusst klein: Der gemeinsame Bestandsbenutzer wird mit seinem bisherigen Passwort und kompatiblen Rechten übernommen und danach schrittweise eingeschränkt.

## 2. Geltungsbereich: sämtliche MQTT-Clients

Das Konzept gilt für physische Geräte ebenso wie für Anwendungen und Docker-basierte Services. Anwendungen werden gleich behandelt, egal ob sie als Container, in einer VM oder auf einem anderen Host laufen.

| Kategorie | Client / Anwendung | Erste Berechtigungsidee |
|---|---|---|
| Device | Tasmota-Geräte | Eigene Topics; Tasmota-spezifisches Profil |
| Device | Andere MQTT-Geräte (z. B. Zähler-Auslesung) | Definierte Mess- und gegebenenfalls Steuer-Topics |
| Application | TasmoFleet | Für Geräteverwaltung benötigte Topics |
| Application | Smart-Home-Zentrale (z. B. Home Assistant) | Freigegebene Status- und Telemetrie-Topics, einzelne Befehle |
| Application | Steuerungs- und Automatisierungsdienste | Benötigte Sensorwerte lesen, definierte Befehle publizieren |
| Application | Datendienste (z. B. Energie- oder Wetterprognosen) | Benötigte Daten lesen bzw. eigene Daten publizieren |
| Application | Gateways zu anderen Systemen (z. B. KNX) | Explizit konfigurierte Topics |
| Application / Docker | MQTT Viewer | Lesender Zugriff auf freigegebene Topics |
| Service | PMSS | Nur `$CONTROL/dynamic-security/#`, kein Zugriff auf Nutz-Topics |

Die Tabelle nennt typische Kategorien. Die konkreten Clients und Rechte werden aus dem Topic-Inventar abgeleitet (Abschnitt 6.3).

### 2.1 Identität pro Client

Ein Client-Objekt enthält mindestens:

- eindeutige interne Kennung,
- Anzeigename,
- Client-Kategorie (Device oder Application),
- Hersteller bzw. Anwendung, falls bekannt,
- MQTT-Benutzername,
- zugeordnetes Berechtigungsprofil,
- optionale individuelle Topic-Ausnahmen,
- Aktivierungsstatus,
- TLS-fähig: ja / nein / unbekannt,
- TLS erforderlich: ja / nein – „ja“ bedeutet Anmeldung per Zertifikat der App-CA ohne Passwort (Abschnitt 7.1),
- HTTP-Zugang verfügbar: ja / nein (Rückfallpfad, siehe 6.2),
- Notizen.

Client-ID und Benutzername sind nicht dasselbe. Dynamic Security unterscheidet Benutzername und optional eine fest zugeordnete Client-ID.

**Benutzernamen** (PMSS 5.4, 6.4):

- Passwort-Clients: ohne `=` und `,`, z. B. das Tasmota-Topic.
- Zertifikats-Clients: Subject des App-Zertifikats, z. B. `CN=homeassistant,O=mqtt-apps`, ohne Passwort.
- `pmss-*` ist für die Admin-Identitäten und ihre Nachfolger (`pmss-admin-2` usw.) reserviert.
- Tasmota-Topics dürfen nicht mit `pmss-` beginnen und kein `=` oder `,` enthalten; TasmoFleet blockiert Geräte mit unzulässigem Topic.

**Verwaltete Objekte** (D-14, Frage 24): Rollen und Gruppen, die PMSS verwaltet, tragen das Präfix `tf_` (z. B. `tf_role_tasmota`). Clients behalten ihren Namen und werden in `textdescription` mit `managed-by: pmss` gekennzeichnet. PMSS ändert nur verwaltete Objekte; was mit `mosquitto_ctrl` angelegt wurde, bleibt geschützt.

## 3. Fachliches Berechtigungsmodell

Das Modell unterscheidet:

1. **Clients / Identitäten** – einzelne Geräte und Anwendungen.
2. **Berechtigungsprofile** – wiederverwendbare fachliche Regeln, in DynSec als Rollen abgebildet.
3. **Topic-Berechtigungen** – konkrete Publish- und Subscribe-Rechte.
4. **Individuelle Ausnahmen** – zusätzliche oder eingeschränkte Rechte eines einzelnen Clients.

### 3.1 Publish und Subscribe getrennt behandeln

Das Modell unterscheidet:

- Nachrichten publizieren (`publishClientSend`),
- Topic-Filter abonnieren (`subscribePattern` / `subscribeLiteral`),
- Nachrichten empfangen (`publishClientReceive`).

Ein erfolgreiches SUBSCRIBE bedeutet nicht, dass Nachrichten zugestellt werden dürfen. Beides muss abgesichert sein. Im Test bestätigt: Home Assistant erhält für `stat/#` ein SUBACK „Granted“, die FILEDOWNLOAD-Nachricht wird trotzdem nicht zugestellt.

`publishClientReceive` und `unsubscribe` sind in DynSec standardmäßig erlaubt. Deny-by-default (D-16) wird bei der Ersteinrichtung mit `setDefaultACLAccess` gesetzt: `publishClientSend`, `publishClientReceive` und `subscribe` deny, `unsubscribe` allow (PMSS 6.2). Das ist nicht Teil der REST-API v1, sondern bleibt bei `mosquitto_ctrl`. ✅ Geprüft.

### 3.2 Beispielhafte Berechtigungsprofile

| Profil | Lesen / Subscribe | Schreiben / Publish |
|---|---|---|
| Tasmota Device | Eigene Command-Topics | Eigene Status- und Telemetrie-Topics |
| Mess- und Zählergeräte | Erforderliche Steuer-/Status-Topics | Eigene Messwerte |
| TasmoFleet Service | Status-, Telemetrie- und Antwort-Topics | Erforderliche Command-Topics |
| Home Assistant | Freigegebene Status-, Telemetrie- und Discovery-Topics | Freigegebene Command- und Discovery-Topics |
| MQTT Monitor / Viewer | Freigegebene Topics | Keine |
| Steuerungs- und Automatisierungsdienst | Benötigte Sensor- und Statusdaten | Definierte Befehle |
| Datendienst (z. B. Prognosen) | Benötigte Eingangsdaten | Eigene Prognose-/Statusdaten |
| Gateway zu anderem System | Explizit konfigurierte Topics | Explizit konfigurierte Topics |
| Legacy (Übergang) | Alles unter `#`, kein `$SYS/#`, kein `$CONTROL/#` | Alles unter `#` |

**Befehlsrechte für Anwendungen:** Publish auf `cmnd/+/#` bedeutet volle Kontrolle über die Geräte, einschließlich `MqttPassword`, `Reset` und `Backlog`. Anwendungen wie Home Assistant werden, wo möglich, auf einzelne Befehle begrenzt (z. B. `cmnd/<topic>/POWER`).

### 3.3 Regeln über die Client-ID sind keine Sicherheitsgrenze

Solange sich mehrere Geräte einen Benutzer teilen, lassen sich Rechte pro Gerät nur über die Client-ID trennen (`%c`). Die Client-ID wird nicht authentifiziert. Solche Regeln schützen gegen Fehlkonfiguration, nicht gegen einen kompromittierten Client. Echte Trennung entsteht erst mit individuellen Zugangsdaten (Abschnitt 6). Deshalb werden die Rechte erst eingeschränkt, wenn individuelle Zugangsdaten verteilt werden können (Abschnitt 9).

## 4. Tasmota-Topics und Namenskonvention

Grundlage ist `docs/mqtt-broker-acl.md` im TasmoFleet-Repository. Die Regeln dürfen nicht ungeprüft als vollständiges Modell übernommen werden.

**Konvention:** Der MQTT-Benutzername eines Tasmota-Geräts entspricht seinem Tasmota-`Topic`. Damit genügt ein generisches Profil mit `%u`. ✅ Beschlossen (D-15); der Benutzername erhält deshalb kein Präfix.

DynSec ersetzt `%u` und `%c` erst ab Mosquitto **2.1**. In 2.0.x werden ACL-Topics wörtlich verglichen, `cmnd/%u/#` passt dann nie. Mit 2.1.2 funktioniert das Profil (Rolle `role_tasmota`, Gruppe `group_tasmota`). ✅ Geprüft.

| Richtung | Topic | Hinweis |
|---|---|---|
| Subscribe | `cmnd/%u/#` | Eigene Befehle |
| Subscribe | `cmnd/<GroupTopic1…4>/#` | Bis zu vier pro Gerät |
| Subscribe | `cmnd/<FallbackTopic>/#` | Enthält die MAC, z. B. `cmnd/<mac>_fb/#` |
| Publish | `stat/%u/#` | Antworten, auch FILEDOWNLOAD |
| Publish | `tele/%u/#` | Telemetrie, inklusive LWT (retained) |
| Publish | `tasmota/discovery/<MAC>/#` | Hängt an der MAC, nicht am Topic |

GroupTopic, FallbackTopic und Discovery passen nicht in das Schema mit `%u`.

**Rolle pro Gerät** (D-53, Spezifikation S-7, PMSS 6.4): Diese Topics stehen in einer eigenen Rolle je Gerät mit dem Namen `tf_role_dev_<mac>`: MAC in Kleinbuchstaben, 12 Hex-Zeichen ohne Trennzeichen, z. B. `tf_role_dev_a4cf12345678`. Das Topic steht im `textname` der Rolle. Ändert sich das Topic, entsteht ein neuer Client; die Geräterolle bleibt.

**GroupTopic1–4:** Das Profil muss alle tatsächlich gesetzten GroupTopics erlauben. Ab TasmoFleet 0.42.0 werden alle vier gelesen (hellwand/tasmofleet#1005). Ein Gerät mit ungelesenen GroupTopics gilt für die Profilerzeugung als unvollständig. Publish-Rechte auf ein GroupTopic sind wie `cmnd/+/#` zu behandeln.

**Sensible Antworten:** `stat/<topic>/FILEDOWNLOAD` enthält Backup-Inhalte. Anwendungen mit Leserecht auf `stat/#` werden davon per Deny-Regel ausgeschlossen. In DynSec: `publishClientReceive` deny auf `stat/+/FILEDOWNLOAD` mit höherer Priorität als die Allow-Regel. ✅ Mit 2.1.2 geprüft:

```
addRoleACL role_homeassistant publishClientReceive stat/# allow
addRoleACL role_homeassistant publishClientReceive stat/+/FILEDOWNLOAD deny 10
```

Ohne Priorität haben beide Regeln Priorität 0 und die Reihenfolge ist nicht festgelegt.

**ACL-Felder in der PMSS-API** (Frage 29, PMSS v0.11): `acltype` und `topic` sind Pflicht, `allow` ist **Pflicht ohne Standardwert** (DynSec legt ohne `allow` eine Deny-Regel an), `priority` ist optional (Standard 0). Hat eine Deny-Regel keine höhere Priorität als eine Allow-Regel desselben Typs in derselben Rolle, gibt PMSS einen Warnhinweis (`warnings` in der Antwort).

Die Legacy-Rolle der ersten Migration liest FILEDOWNLOAD weiterhin, wie vor der Migration. Das endet mit der Ablösung der Legacy-Rolle.

## 5. Architektur

### 5.1 Drei Ebenen

| Ebene | Aufgabe | Technik |
|---|---|---|
| 1. Externe Administration | TasmoFleet und Administratoren ändern Clients, Profile und Zugangsdaten | REST-API nach Schnittstellenspezifikation v1 (`/api/v1/…`), umgesetzt von PMSS, über HTTPS (NPM), nur Tokens des OIDC-Providers (Keycloak oder authentik) |
| 2. Interne Verwaltung | PMSS setzt Änderungen am Broker um | MQTT 5 über TLS im privaten Docker-Netz, Port 8884, nur Admin-Zertifikat, `$CONTROL/dynamic-security/v1` |
| 3. MQTT-Zugriff | Geräte und Anwendungen verbinden sich und nutzen Topics | Authentifizierung und Topic-Rechte durch Dynamic Security, Listener 1883, 8883, 8885 |

```
Administrator ──┐
                ├─ HTTPS + OIDC-Token ─────► NPM ─► PMSS ─ MQTT/mTLS :8884, Admin-Zertifikat (privates Netz) ─► Mosquitto + DynSec
TasmoFleet ─────┘                                                                                                ▲
                                                       MQTT :1883 (IoT-Netz, Passwort) ──────────────────────────┤
                                                       MQTTS :8883 (TLS, Passwort) ──────────────────────────────┤
                                                       MQTTS :8885 (nur App-Zertifikat) ─────────────────────────┘
                                                                     Geräte und Anwendungen
```

### 5.2 Rollen der Komponenten

**PMSS**

- ist der einzige DynSec-Admin am Broker (Identität `pmss-admin`),
- ist die Referenz-Implementierung der Schnittstellenspezifikation v1 (D-52),
- speichert keinen Zustand; liefert den Ist-Zustand der verwalteten Objekte über `GET /api/v1/export`,
- meldet sich nur per Zertifikat der Admin-CA an, ohne Passwort,
- verwaltet nur Rollen und Gruppen mit Präfix `tf_` und Clients mit Kennzeichnung `managed-by: pmss`; fremde Objekte bleiben unverändert (PMSS SEC-27),
- setzt die Namensregeln durch: `pmss-*` und `role_security_manager` reserviert, kein Passwort für `CN=`-Clients, kein `=`/`,` in Namen von Passwort-Clients,
- prüft jedes Token gegen den OIDC-Provider (Signatur über JWKS, Issuer, Audience, Ablaufzeit, `scope`-Claim, Scopes `read`/`write`),
- protokolliert jede Änderung mit dem Benutzer aus dem Token.

Details zur API stehen in der Schnittstellenspezifikation, zu Deployment und Implementierung im PMSS-Detaildokument.

**Admin-Rolle `role_security_manager`:** `mosquitto_ctrl dynsec init` legt die Rolle `admin` mit Lesezugriff auf `#` an. Sie wird bei der Ersteinrichtung durch `role_security_manager` ersetzt und gelöscht. `role_security_manager` darf nur `$CONTROL/dynamic-security/#` und `$SYS/#`. ✅ Im Test bestätigt: Der Admin kann DynSec verwalten, aber weder `tele/#` noch FILEDOWNLOAD lesen noch auf `cmnd/…` publizieren.

**Admin-Identitäten:** `pmss-admin` (PMSS) und `pmss-breakglass-admin` (Notfall, offline). Gesperrt wird ein Admin-Zertifikat mit `deleteClient`, nicht mit `disableClient`. Ein Nachfolger erhält eine fortlaufende Nummer (`pmss-admin-2`), denn unter dem alten Namen hätte auch das alte Zertifikat wieder Admin-Rechte.

**TasmoFleet**

- bietet die Oberfläche für Clients, Profile, Ausnahmen und die Umstellung der Geräte,
- kennt die Tasmota-Topics (GroupTopics, FallbackTopic, MAC) und leitet daraus Profile und Geräterollen `tf_role_dev_<mac>` ab,
- hält den Soll-Zustand, berechnet den Diff gegen den Export von PMSS, holt die Freigabe von `security-admin` ein und zeigt den Drift-Report (Abschnitt 7.3),
- schreibt neue Zugangsdaten per `Backlog` auf die Geräte (Abschnitt 6.2),
- verteilt bei Erneuerung des Server-Zertifikats den neuen Fingerprint an Tasmota-Geräte mit TLS,
- stellt später App-Zertifikate aus (Zwischen-CA mit CRL oder eigene TasmoFleet-CA, Frage 30),
- spricht mit dem Broker nur als normaler MQTT-Client, nie als DynSec-Admin,
- ruft für Änderungen an Rechten und Zugangsdaten die REST-API nach Schnittstellenspezifikation v1 auf, mit einem per Token Exchange getauschten Token des angemeldeten Benutzers; das setzt den OIDC-Login voraus (Abschnitt 7.2).

**Broker**

- Mosquitto ab 2.1 (getestet mit 2.1.2, Integrationstests und Produktion mit 2.1.4) mit Dynamic Security, z. B. in [IOTstack](https://github.com/SensorsIot/IOTstack) (Docker Compose),
- Initialisierung und Aktivierung des Plugins bleiben Aufgabe des Broker-Administrators; die Ersteinrichtung läuft offline in einem Container ohne Netzwerk (PMSS 6.2).

### 5.3 Ausgangszustand und Ziel

| Zustand | Verwaltung | Einordnung |
|---|---|---|
| Ausgangszustand | `password_file`, gegebenenfalls `acl_file` | Wird abgelöst |
| Phase 0 | DynSec mit `mosquitto_ctrl` | Manuell, kleine erste Migration |
| Ziel | DynSec über PMSS, Oberfläche in TasmoFleet | Kein direkter Broker-Zugriff durch TasmoFleet |

Classic ACL ist kein Ziel-Backend mehr. Ein ACL-Export aus TasmoFleet ist zurückgestellt (D-17).

Ohne aktive ACL-Datei haben authentifizierte Clients Zugriff auf alle Topics. Mit einem gemeinsamen Benutzer hilft auch eine ACL-Datei nur eingeschränkt (Abschnitt 3.3).

### 5.4 Hinweis zum Upstream-Projekt

TasmoFleet ist ein Upstream-Projekt (hellwand/tasmofleet), PMSS ein eigenes Projekt. Damit TasmoFleet upstream nicht von PMSS abhängt, läuft die Anbindung über die **Schnittstellenspezifikation „MQTT Security Service API v1“** (`mqtt-security-service-api-v1`, D-52, Frage 16). Sie legt Pfade, Felder, Statuscodes, Fehlercodes, `ETag`-Regeln und Beispiele verbindlich fest, dazu die Anforderungen an den OIDC-Provider und die Regeln für den Token Exchange. PMSS ist die Referenz-Implementierung; jede andere Implementierung der Spezifikation kann PMSS ersetzen. Bei Abweichungen gilt die Spezifikation.

## 6. Individuelle MQTT-Zugangsdaten und Migration

Individuelle Zugangsdaten pro Gerät und Anwendung sind die eigentliche Sicherheitsmaßnahme. Ohne sie bleibt die Trennung eine Regel über die Client-ID (Abschnitt 3.3).

### 6.1 Migrationsprinzipien

1. Bestehende Clients, Zugangsdaten und Topic-Nutzung erfassen.
2. Zielidentitäten und Profile vorbereiten.
3. Neue Berechtigungen am Broker bereitstellen.
4. Einen Client bzw. eine kleine Gruppe umstellen.
5. Verbindung und erlaubte/unerlaubte Kommunikation prüfen.
6. Erst danach alte Berechtigungen bzw. gemeinsame Zugangsdaten zurücknehmen.

Die Migration setzt nicht voraus, dass alle Geräte gleichzeitig umgestellt werden. Ein Rückfallpfad ist vorgesehen.

**Erste Migration (Phase 0):** Der gemeinsame Bestandsbenutzer `legacy-shared-user` wird mit seinem **bisherigen Passwort** in DynSec übernommen (Entscheidung Frage 26, D-30):

- DynSec speichert Passwörter im selben `$7$`-Format wie `pwfile`. Der Hash wird mit `import-pwfile.py` übernommen. Voraussetzung: Die `pwfile` enthält `$7$`-Hashes (vorher prüfen). ✅ Übernahme geprüft.
- Kein Gerät und keine Anwendung wird angefasst; es gibt kein Migrationsfenster für Passwörter.
- Rechte über die Legacy-Rolle `role_legacy`: alles unter `#`, aber kein `$SYS/#` und kein `$CONTROL/#`. Anwendungen, die `$SYS` abonnieren, verlieren diesen Zugriff.
- `legacy-shared-user` und `role_legacy` sind für PMSS nicht verwaltet (keine Kennzeichnung, kein Präfix). Änderungen nur per Break-glass; gelöscht wird beim Aufräumen.
- **Rückfallweg:** `pwfile` bleibt unverändert liegen. Zurück geht es durch Zurückspielen der gesicherten `mosquitto.conf` und Neustart. Aufgeräumt wird nach Phase 4 (Abschnitt 9).

Danach werden einzelne Clients auf eigene Benutzer umgestellt und die Rechte eingeschränkt.

### 6.2 Zugangsdaten auf Geräte verteilen

1. TasmoFleet fordert bei PMSS einen neuen Client an.
2. PMSS legt den Client in DynSec an, erzeugt das Passwort und gibt es einmalig an TasmoFleet zurück (Frage 25).
3. TasmoFleet überträgt es per `Backlog MqttUser <user>; MqttPassword <passwort>` auf das Gerät.
4. Das Gerät verbindet sich neu.
5. TasmoFleet prüft die Verbindung und die erlaubte Kommunikation.

**Passwörter** (D-41, D-42): Der Aufrufer kann ein Passwort mitgeben; fehlt es, erzeugt PMSS eines. Jedes Passwort besteht aus genau 24 Zeichen `A–Z a–z 0–9`. Grund: In `Backlog` trennt `;` die Befehle und ein Leerzeichen Befehl und Wert. Tasmota verlangt mindestens 5 Zeichen und setzt keine Höchstlänge.

**Passwortwechsel:** Ein Passwortwechsel ändert das `ETag` des Clients nicht (Spezifikation S-5). Zwei gleichzeitige Wechsel für denselben Client wären daher beide erfolgreich; TasmoFleet lässt je Client nur einen laufenden Passwortwechsel zu (Spezifikation 4.4).

**Berechtigung:** Neue Zugangsdaten auf Geräte schreiben darf nur `security-admin` (D-25).

**Rückfallpfad:** Bei falschen Zugangsdaten ist das Gerät per MQTT nicht mehr erreichbar. Der Rückweg führt über die HTTP-API des Geräts. Geräte mit `SetOption128 1` (HTTP-API deaktiviert) haben keinen Rückweg; TasmoFleet prüft das vorher und blockiert oder warnt.

**Entschieden (D-54, Frage 15):** TasmoFleet speichert Passwörter nicht dauerhaft, sondern nur bis zur erfolgreichen Übertragung auf das Gerät bzw. bis zum Abbruch der Umstellung. PMSS gibt ein erzeugtes Passwort nur einmal heraus.

**Noch zu klären:**

- Rotation von Passwörtern,
- Versorgung von Geräten und Anwendungen ohne Tasmota.

### 6.3 Topic-Inventar erfassen

Wer `#` abonniert, sieht nicht, welcher Client publiziert hat. Die Zuordnung ist nur über den Broker möglich: Mosquitto mit Debug-Logging („Received PUBLISH from <clientid>“).

**Festgelegt (Frage 28):**

- Beobachtung **eine Woche** nach dem Funktionstest der ersten Migration, ohne Sperren; danach wird das Debug-Logging abgeschaltet. Ein- und Ausschalten per SIGHUP, ohne Neustart. ✅ Geprüft.
- **Log-Ziel:** ein zentraler Syslog-Dienst, z. B. [phylax-syslog-service](https://github.com/Noschvie/phylax-syslog-service), über den Docker-Logging-Treiber `syslog` (PMSS 6.6).
- **Beobachten und Einschränken sind getrennt:** Die Beobachtung läuft parallel zu den TLS-Listenern und zur PMSS-Einführung; eingeschränkt wird erst danach (Abschnitt 9).
- Die Logs enthalten Client-IDs, Benutzernamen, IP-Adressen und Topics, keine Nutzdaten.

Werkzeug: `mqtt-acl-verify inventory <log> -p -u -x` wertet die Log-Dateien des Syslog-Dienstes aus, inklusive verweigerter Publishes. Der Parser akzeptiert Syslog-Kopfzeilen und den Tabulator als `#011`.

## 7. Sicherheit und Betriebsgrenzen

- TasmoFleet erhält keine DynSec-Admin-Rechte.
- Administrative Zugangsdaten (Admin-Zertifikate) liegen nur bei PMSS bzw. offline (Break-glass).
- Der DynSec-Admin hat keinen Zugriff auf Nutz-Topics (`role_security_manager`, Abschnitt 5.2).
- Zugangsdaten erscheinen nicht in Logs, Diagnoseausgaben, Fehlerantworten oder ungeschützten Exporten.
- Änderungen an Berechtigungen werden in PMSS mit Benutzer, Zeitpunkt sowie Vorher- und Nachher-Zustand protokolliert.
- Unbekannte oder nicht verwaltete Clients werden nicht pauschal freigeschaltet.
- Vor Änderungen wird der Ist-Zustand gesichert: TasmoFleet legt den Export ab, der Host sichert `dynamic-security.json` regelmäßig.
- Ein Fehler in TasmoFleet darf nicht alle Broker-Berechtigungen überschreiben; PMSS ändert nur verwaltete Objekte (Präfix `tf_` bzw. Kennzeichnung).
- Alte retained Messages (z. B. Discovery) bleiben bei Rechteänderungen liegen. Der Umgang damit ist festzulegen.

### 7.1 Transportsicherheit

TLS lässt sich nicht für alle Clients vorschreiben. Entschieden (Fragen 19, 20; PMSS v0.8):

| Listener | Netz (Firewall am Router) | Zweck | Anmeldung |
|---|---|---|---|
| 1883, Klartext | IoT-Netz | Geräte und Anwendungen ohne TLS | Passwort |
| 8883, TLS | LAN, bei Bedarf IoT-Netz | Clients mit TLS, z. B. Tasmota mit TLS | Passwort |
| 8885, TLS | LAN | Anwendungen mit „TLS erforderlich“ | Nur Zertifikat der App-CA, Benutzername = Subject |
| 8884, TLS (intern) | Privates Docker-Netz, nicht veröffentlicht | Nur DynSec-Admins | Nur Zertifikat der Admin-CA, Benutzername = CN |

Die Netzbeschränkung erfolgt per Firewall-Regel am Router und ist nicht Teil dieses Projekts. TLS-Mindestversion ist 1.2 (Tasmota).

**Zertifikate:**

| CA | Zweck |
|---|---|
| Server-CA | Server-Zertifikate: intern (SAN `mosquitto`, Port 8884) und extern (SAN `mqtt.example.org`, RSA, 12 Monate, Ports 8883 und 8885) |
| Admin-CA | Nur Zertifikate für `pmss-admin` und `pmss-breakglass-admin` |
| App-CA | Nur Zertifikate für Anwendungen, Subject `/O=mqtt-apps/CN=<name>`; später stellt TasmoFleet sie aus (Form offen, Frage 30). Ein kompromittiertes Zertifikat wird mit `deleteClient` gesperrt; der Nachfolger bekommt ein neues Subject (z. B. `CN=homeassistant-2`), sonst gilt das alte Zertifikat wieder |

Alle CA-Schlüssel liegen offline. Jeder Listener mit Client-Zertifikaten vertraut genau einer Client-CA.

**Admin nur über TLS, am Broker durchgesetzt (D-20, Fragen 17, 18, 27):** Die Admins haben kein Passwort und melden sich nur per Zertifikat der Admin-CA an 8884 an (`use_identity_as_username`). Ein Client ohne Passwort kann sich an keinem Passwort-Listener anmelden. Der Listener 8884 wird vor der DynSec-Aktivierung eingerichtet, die Ersteinrichtung läuft offline, und der Bootstrap-Admin aus `dynsec init` wird danach gelöscht. Zu keinem Zeitpunkt kann sich ein Admin über 1883 anmelden.

**„TLS erforderlich“ (D-21, Frage 20):** DynSec kennt keine Bindung eines Clients an einen Listener; ein Passwort gilt an 1883 und 8883 gleichermaßen. Durchsetzbar ist TLS nur über Zertifikats-Clients: Ein Client mit „TLS erforderlich“ hat kein Passwort und meldet sich per App-Zertifikat an 8885 an. ✅ Geprüft: Sein Name wird an 1883 und 8883 abgelehnt.

**Keine Kollision zwischen App- und Admin-Zertifikaten:** Am App-Listener ist der Benutzername das vollständige Subject (`use_subject_as_username`). Ein App-Zertifikat mit `CN=pmss-admin` wird zu `CN=pmss-admin,O=mqtt-apps` und hat keine Admin-Rechte. ✅ Geprüft.

**Jährliche Erneuerung des Server-Zertifikats:** Tasmota prüft die eigene CA per Fingerprint. Der neue Fingerprint wird vorher in `MqttFingerprint2` eingetragen, dann wird das Zertifikat getauscht (PMSS 5.4).

**Restrisiko:** Ohne TLS kann jemand im Netz der Geräte Zugangsdaten mitlesen. Das Risiko bleibt, bis die betroffenen Clients TLS unterstützen; es wird durch die Netztrennung begrenzt.

### 7.2 OIDC-Provider (Keycloak, authentik)

**Grundsatz:** Die REST-API von PMSS akzeptiert nur Tokens des konfigurierten OIDC-Providers, bei dem sich die Benutzer an TasmoFleet anmelden (D-55, ersetzt D-28). Getestet sind Keycloak und authentik. PMSS prüft Signatur (JWKS), Issuer, Audience, Ablaufzeit, das `scope`-Claim und die Scopes `read`/`write`, keine Rollen oder Gruppen (Frage 21, Spezifikation 2.1).

**Menschen – Rolle `security-admin`** (D-22, beschlossen)

- Eigene Rolle bzw. Gruppe im Provider, kein Zusatzrecht von `admin`.
- Zweiter Faktor (OTP oder WebAuthn) über einen bedingten Anmeldeablauf im Provider, nur für `security-admin`, für alle Anmeldewege, die zu einem Token mit Scope `write` führen (Browser, Device Authorization Grant, Token Exchange danach). PMSS prüft `acr`/`amr` nicht (Frage 22).
- Der Provider gibt `write` nur an `security-admin` aus. Damit wird D-22 im Provider durchgesetzt, und PMSS bleibt unabhängig von TasmoFleet-Rollen.
  - **Keycloak:** Rollen-Zuordnung am Client-Scope `write`. Ohne `security-admin` antwortet der Token Exchange mit `200` und `scope=read`. ✅ Mit Keycloak 26.8.2 bestätigt, auch für Service-Accounts (PMSS 7.9, `test/integration/keycloak`).
  - **authentik:** Expression-Policy an der Application von PMSS. Ohne `security-admin` lehnt authentik die ganze Anfrage mit `write` ab (`400 invalid_grant`). ✅ Mit authentik 2026.8.6 bestätigt (PMSS 7.9, `test/integration/authentik`).

| Funktion | operator | admin | security-admin |
|---|---|---|---|
| Geräte ansehen, Befehle senden | ✅ | ✅ | ❌ |
| Geräte konfigurieren, Backup/Restore | ❌ | ✅ | ❌ |
| MQTT-Clients, Profile und Ausnahmen verwalten | ❌ | ❌ | ✅ |
| Änderungen am Broker prüfen (Diff) und anwenden | ❌ | ❌ | ✅ |
| MQTT-Zugangsdaten erzeugen, ändern, sperren | ❌ | ❌ | ✅ |
| Neue MQTT-Zugangsdaten auf Geräte schreiben | ❌ | ❌ | ✅ |
| Audit-Log der Freigaben in TasmoFleet einsehen | ❌ | lesend | ✅ |

Rollen ohne Security-Recht sehen keine MQTT-Zugangsdaten, auch nicht maskiert.

**Audit:** TasmoFleet führt ein eigenes Audit der Freigaben (wer hat welchen Diff freigegeben); dieses darf `admin` lesen. Das Audit von PMSS (Vorher- und Nachher-Zustand) geht ins Log an den zentralen Syslog-Dienst, Zugriff nur für den Betrieb. PMSS hat keinen Audit-Endpunkt.

**Tokens** (Fragen 14, 22; D-31):

| Aufrufer | Ablauf | Scopes |
|---|---|---|
| TasmoFleet im Auftrag eines Benutzers | Token Exchange (RFC 8693) beim selben Provider: Benutzer-Token gegen Token mit `aud` = PMSS tauschen; `sub` bleibt der Benutzer | `read`, `write` nur bei `security-admin` |
| Administrator per `curl` | Device Authorization Grant, Anmeldung im Browser mit zweitem Faktor | `read`, `write` nur bei `security-admin` |
| Skripte, Monitoring, Drift-Prüfung | Client Credentials (Service-Account) | nur `read` |
| Automatische Tests | Client Credentials in der Testumgebung | `read`, `write` |

In Produktion hat kein Service-Account den Scope `write`, denn ein Service-Account hat keinen zweiten Faktor. TasmoFleet ist ein vertraulicher Client mit aktiviertem Token Exchange. `GET /api/v1/export` und `GET /api/v1/info` brauchen nur `read`.

**Regeln für TasmoFleet** (Spezifikation S-16, S-17):

- Der Security Manager setzt den OIDC-Login voraus (`TASMOFLEET_AUTH_MODE=oidc`). Im Header-Modus und mit lokalen Konten gibt es kein Benutzer-Token zum Tauschen.
- TasmoFleet tauscht ein gültiges Access-Token der Sitzung und erneuert es vorher bei Bedarf.
- TasmoFleet fragt `write` nur für `security-admin` an, fällt bei Ablehnung einmal auf `read` zurück und wertet in jedem Fall `scope` des getauschten Tokens aus.
- TasmoFleet holt Tokens über dieselbe öffentliche URL wie der Login. authentik bildet den Issuer aus dem Hostnamen der Anfrage; ein Token über einen anderen Namen lehnt PMSS ab.

**Unterschiede zwischen den Providern** (PMSS 7.5, T-8, T-9):

| Thema | Keycloak | authentik |
|---|---|---|
| Fester Issuer | `KC_HOSTNAME` | Alle Aufrufer über dieselbe öffentliche URL |
| `write` ohne `security-admin` | `200`, `scope=read` | `400 invalid_grant` |
| Erkennen von Access-Tokens | Claim `typ` = `Bearer` | `scope`-Claim und Audience; kein `typ`-Claim |
| `azp` im getauschten Token | TasmoFleet | PMSS |
| Token Exchange | Standard Token Exchange am TasmoFleet-Client | Grant „Token exchange“, PMSS-Provider vertraut dem TasmoFleet-Provider |
| Konfiguration als Code | Realm-JSON | Blueprint |
| Mindestversion | 26.2 | 2026.8.3 |

**Abhängigkeit vom Provider:** Ist der Provider nicht erreichbar, können keine neuen Tokens ausgestellt und damit keine Berechtigungen geändert werden. Bereits ausgestellte, gültige Tokens prüft PMSS weiter mit den gecachten JWKS-Schlüsseln. Geräte sind nicht betroffen. Für den Notfall bleibt `mosquitto_ctrl` mit dem Zertifikat `pmss-breakglass-admin` (Break-glass, überwacht; D-24).

Da PMSS jedes Token bei jeder Anfrage prüft, entfällt das Problem aus v0.2, dass MQTT ein Token nur beim CONNECT prüft.

### 7.3 Soll-Zustand, Diff und Drift

Entschieden (Frage 23, PMSS v0.11). PMSS speichert keinen Zustand; alles, was einen Zustand braucht, liegt in TasmoFleet oder beim Host. Pfade nach Schnittstellenspezifikation v1.

| Aufgabe | Wo | Umsetzung |
|---|---|---|
| Soll-Zustand (Clients, Profile, Ausnahmen) | TasmoFleet | Fachliches Modell |
| Ist-Zustand | PMSS | `GET /api/v1/export`: alle verwalteten Objekte als ein JSON, mit `etag` je Objekt, sortiert nach Unicode-Codepunkten |
| Diff und Freigabe | TasmoFleet | Soll gegen Export; angewendet wird erst nach Freigabe durch `security-admin` |
| Sicherung vor dem Anwenden | TasmoFleet | Export ablegen |
| Sicherung unabhängig von TasmoFleet | Host | `dynamic-security.json` regelmäßig sichern; Grundlage auch für Break-glass |
| Drift-Report | TasmoFleet | Soll gegen Export, ohne anzuwenden; zeigt auch Änderungen per Break-glass |
| Schutz nicht verwalteter Objekte | PMSS | Präfix `tf_` und Kennzeichnung `managed-by: pmss` (D-39) |
| Gleichzeitige Änderungen | PMSS | `ETag` in `GET`, `If-Match` Pflicht bei Änderungen, sonst `412` bzw. `428`; jede Beziehung gehört genau einem Objekt (Gruppenzugehörigkeit gehört der Gruppe) |
| Nachvollziehbarkeit | PMSS | Audit mit Vorher- und Nachher-Zustand, ohne Passwörter |
| ACL-Liste einer Rolle ändern | PMSS | `PUT /api/v1/roles/{role}/acls` per `modifyRole` in einem Schritt, danach Zurücklesen und Vergleich |
| Rolle mit ACLs anlegen | PMSS | `POST /api/v1/roles` mit `acls`, Zurücklesen, bei Abweichung wieder löschen |
| Teilerfolg bei mehreren Kommandos | PMSS | Ausgleichsweg: angelegten Client bzw. angelegte Rolle wieder löschen, Fehler melden |
| Fehler | PMSS | `application/problem+json` (RFC 9457) mit `status` und festem `code` |

Gegen Fehler in TasmoFleet schützen damit: der begrenzte Wirkungsbereich (nur verwaltete Objekte), die Validierung in PMSS, `If-Match`, das Audit mit Vorher-Zustand und die Host-Sicherung.

## 8. Validierung und Tests

Der Testsatz `mqtt-acl-verify` wird gegen den Broker ausgeführt, vor und nach jeder Phase. Testbasis ist Mosquitto 2.1.2 mit DynSec (`testbroker-dynsec/`), derzeit 59 Fälle plus CI-Schritte für Control-API und `$SYS`. Die Testfälle zur Schnittstellenspezifikation und zu den Identity Providern stehen im PMSS-Dokument (Abschnitt 7.9); Keycloak und authentik haben getrennte Testumgebungen.

Spalte „Geprüft“: ✅ = geprüft, Ergebnis wie erwartet (Broker-Fälle mit `mqtt-acl-verify` gegen den Test-Broker 2.1.2, Token-Fälle mit `check_tokens.py` des jeweiligen Providers); ⚠️ = geprüft, Ergebnis weicht ab bzw. bekannte Schwäche; leer = noch nicht geprüft.

| Testfall | Erwartung | Geprüft |
|---|---|---|
| TasmoFleet liest Geräte-Status-/Antwort-Topics | Erlaubt | ✅ |
| TasmoFleet publiziert erforderliche Gerätebefehle | Erlaubt | ✅ |
| Tasmota-Gerät empfängt eigene Commands | Erlaubt | ✅ (`%u`, ab 2.1) |
| Tasmota-Gerät empfängt Commands anderer Geräte | Verweigert | ✅ |
| Tasmota-Gerät empfängt Befehle auf jedem seiner GroupTopics (1–4) | Erlaubt | |
| Tasmota-Gerät empfängt Befehle auf einem fremden GroupTopic | Verweigert | |
| Tasmota-Gerät publiziert eigene Status-/Telemetrie-Daten | Erlaubt | ✅ |
| Tasmota-Gerät publiziert in fremde Geräte-Topics | Verweigert | ✅ |
| MQTT Viewer abonniert freigegebene Topics | Erlaubt | ✅ |
| MQTT Viewer publiziert Nachrichten | Verweigert | ✅ |
| Anwendung greift auf nicht freigegebene Topics zu | Verweigert | |
| Unbekannter oder deaktivierter Client verbindet sich (Passwort) | Verweigert | ✅ (unbekannt) |
| Home Assistant empfängt `stat/+/FILEDOWNLOAD` | Verweigert | ✅ |
| Bestandsbenutzer nach Phase 0 mit bisherigem Passwort | Erlaubt, Rechte wie vorher | ✅ (Hash übernommen) |
| Bestandsbenutzer greift auf `$SYS/#` oder `$CONTROL/#` zu | Verweigert | ✅ |
| DynSec-Admin liest Nutz-Topics oder FILEDOWNLOAD | Verweigert | ✅ |
| DynSec-Admin publiziert auf Nutz-Topics | Verweigert | ✅ |
| DynSec-Admin verbindet sich an 1883 oder 8883 | Verweigert | ✅ |
| DynSec-Admin verbindet sich an 8884 mit Admin-Zertifikat | Erlaubt | ✅ |
| Zertifikat der Server-CA oder App-CA an 8884 | Verweigert | ✅ |
| Gelöschter Bootstrap-Admin meldet sich an | Verweigert | ✅ |
| Admin mit `deleteClient` gesperrt | Keine Rechte, offene Verbindung getrennt | ✅ |
| Admin mit `disableClient` gesperrt | Verweigert | ⚠️ Zertifikatsanmeldung bleibt möglich, mit Rechten – nicht verwenden |
| Client ohne gültiges Zertifikat an 8884 oder 8885 | Verweigert | ✅ |
| Zertifikat der Admin-CA mit unbekanntem CN | Keine Rechte | ✅ verbindet sich, ohne Rechte |
| Passwort-Client über TLS an 8883 | Erlaubt, Rechte wie an 1883 | ✅ |
| Anwendung mit App-Zertifikat an 8885 | Erlaubt, Rechte ihrer Rolle | ✅ |
| App-Zertifikat mit `CN=pmss-admin` | Keine Admin-Rechte | ✅ |
| Client mit „TLS erforderlich“ (App-Zertifikat) an 1883 oder 8883 | Verweigert | ✅ |
| TLS-Version unter 1.2 an 8883/8885 | Verweigert | ✅ |
| App-Zertifikat über Zwischen-CA an 8885 | Erlaubt, wenn die Kette mitgeschickt wird | ✅ (manuell) |
| Zwischen-CA per CRL der App-CA widerrufen | Zertifikate der Zwischen-CA abgelehnt | ⚠️ wirkt nicht – Mosquitto prüft die CRL nur für das Client-Zertifikat (manuell) |
| Client-Zertifikat per CRL widerrufen, danach SIGHUP | Abgelehnt | ✅ (manuell) |
| TasmoFleet publiziert auf `$CONTROL/dynamic-security/#` | Verweigert | |
| PMSS-API ohne Token | 401 | |
| PMSS-API mit Token eines fremden Issuers oder abgelaufenem Token | 401 | |
| PMSS-API mit Token ohne `scope`-Claim | 401 | |
| PMSS-API mit Token ohne Scope `write` für Änderungen | 403 | |
| Token Exchange für Benutzer ohne `security-admin` (Keycloak) | Getauschtes Token ohne `write`, Änderung → 403 | ✅ Token ohne `write` (Keycloak 26.8.2) |
| Token Exchange für Benutzer ohne `security-admin` (authentik) | Anfrage mit `write` abgelehnt, mit `read` erfolgreich | ✅ (authentik 2026.8.6) |
| Token Exchange für `security-admin` (Keycloak, authentik) | `aud` = PMSS, `sub` = Benutzer, Änderung erlaubt | ✅ Token wie erwartet (beide) |
| Ursprüngliches TasmoFleet-Token ohne `aud` = PMSS | 401 | ✅ Token ohne `aud` = PMSS (beide) |
| Token Exchange eines Tokens, das nicht für TasmoFleet ausgestellt wurde | Abgelehnt | ✅ (beide) |
| Zweiter Faktor: kein Weg ohne zweiten Faktor zu einem Token mit `write` | Abgelehnt | (manuell, je Provider; authentik zurückgestellt) |
| PMSS ändert ein nicht verwaltetes Objekt (z. B. `legacy-shared-user`, `role_legacy`) | 403 | |
| DynSec: `addRoleACL` ohne `allow` | Deny-Regel | ✅ (manuell) – deshalb `allow` Pflicht in der API |
| DynSec: `modifyRole` mit ungültigem ACL-Eintrag | Fehler | ⚠️ Eintrag wird stillschweigend weggelassen (manuell) – PMSS validiert selbst |
| PMSS-API: ACL ohne `allow` oder mit unbekanntem `acltype` | 422 | |
| PMSS-API: Änderung mit veraltetem `If-Match` | 412, nichts geändert | |
| PMSS-API: `POST /api/v1/clients` mit nicht existierender Rolle | Client wieder gelöscht, Fehler gemeldet | |
| PMSS legt einen Client ohne Passwort an | Antwort enthält 24 Zeichen `A–Z a–z 0–9`, Anmeldung möglich | |
| Mitgegebenes Passwort mit `;`, Leerzeichen oder anderer Länge | 422 | |
| PMSS legt Client `pmss-…` an oder setzt Passwort für `CN=`-Client | Verweigert | |
| Benutzer ohne `security-admin` sieht MQTT-Zugangsdaten | Verweigert | |

Zusätzlich zu prüfen:

- FILEDOWNLOAD und FILEUPLOAD,
- Discovery und Discovery-Konfiguration,
- GroupTopic1–4 und FallbackTopic,
- Retained Messages,
- Wildcard-Subscriptions,
- Priorität von Rollen und ACL-Regeln in DynSec (für FILEDOWNLOAD ✅ geprüft),
- Standardwerte von `setDefaultACLAccess` (✅ geprüft),
- Verhalten bestehender Verbindungen nach Rechteänderungen,
- Reconnect nach Broker-Neustart,
- Rückfallpfad über HTTP bei fehlgeschlagener Umstellung,
- Auswertung eines echten Logs aus dem Syslog-Dienst mit `mqtt-acl-verify inventory`.

Ein erfolgreiches CONNECT oder SUBSCRIBE allein ist kein Sicherheitsnachweis. Geprüft wird, was tatsächlich empfangen und publiziert werden kann.

## 9. Umsetzungsphasen

Die Phasen entsprechen dem PMSS-Detaildokument. Rechte werden erst eingeschränkt, wenn individuelle Zugangsdaten verteilt werden können (Frage 28).

| Overview | PMSS | Inhalt |
|---|---|---|
| Phase 0 | Phasen 0–4 | Erste Migration auf DynSec |
| Phase 1 | Beobachtung, Phase 5 | Topic-Inventar, TLS-Listener 8883 und 8885 |
| Phase 2 | Phase 6 | PMSS |
| Phase 3 | – | TasmoFleet-Anbindung |
| Phase 4 | Phase 7 | Individuelle Zugangsdaten, Rechte einschränken, aufräumen |

### Phase 0 – Erste Migration auf DynSec (PMSS 0–4)

- [ ] Backup von Konfiguration, Passwortdatei und Datenverzeichnis.
- [ ] Hash-Format der `pwfile` prüfen: `$7$`.
- [ ] Anwendungen ermitteln, die `$SYS/#` abonnieren.
- [ ] Server-CA und Admin-CA erstellen, Listener 8884 mit `use_identity_as_username` einrichten – vor der DynSec-Aktivierung.
- [ ] Ersteinrichtung offline: `dynsec init`, Default-Deny, `role_security_manager`, `pmss-admin` und `pmss-breakglass-admin` ohne Passwort, `role_legacy`, `legacy-shared-user`; Rolle `admin` und Bootstrap-Admin löschen.
- [ ] Passwort-Hash von `legacy-shared-user` mit `import-pwfile.py` übernehmen.
- [ ] `password_file` in der Konfiguration abschalten (Datei bleibt liegen), Logging-Treiber `syslog`, Neustart.
- [ ] `mqtt-acl-verify` vorher und nachher ausführen; Funktionstest ohne Änderung an Geräten.

Vorlage für die DynSec-Befehle: PMSS 6.2 und `testbroker-dynsec/dynsec-setup.txt` in `mqtt-acl-verify`.

### Phase 1 – Beobachtung und TLS-Listener

- [ ] Topic-Inventar: eine Woche `log_type all`, danach abschalten; Auswertung mit `mqtt-acl-verify inventory`.
- [ ] App-CA und externes Server-Zertifikat `mqtt.example.org` (RSA, 12 Monate).
- [ ] Listener 8883 (TLS mit Passwort) und 8885 (App-Zertifikat) einrichten; Firewall-Regeln am Router.
- [ ] Client- und Berechtigungsmodell festlegen; Profile aus dem Inventar als DynSec-Rollen entwerfen (noch nicht anwenden).
- [ ] Tasmota-ACL-Dokumentation verifizieren.

### Phase 2 – PMSS

- [ ] Go-Service mit REST-API nach Schnittstellenspezifikation v1, Token-Prüfung für den OIDC-Provider (`scope`-Claim Pflicht, `typ`-Prüfung je Provider), Namensregeln und Audit-Log.
- [ ] Prüfung auf verwaltete Objekte (Präfix `tf_`, Kennzeichnung), Passworterzeugung.
- [ ] `GET /api/v1/info`, `GET /api/v1/export`, `POST /api/v1/roles` mit ACLs, `PUT /api/v1/roles/{role}/acls`, `ETag`/`If-Match`, Fehler nach RFC 9457, Audit mit Vorher- und Nachher-Zustand, Ausgleichsweg.

### Phase 3 – TasmoFleet-Anbindung

- [ ] Schnittstellenspezifikation v1 in TasmoFleet umsetzen (Frage 16, D-52), einschließlich der Regeln für den Token Exchange (S-16, S-17).
- [ ] Im OIDC-Provider (Konfiguration als Code): Rolle bzw. Gruppe `security-admin`, `write` nur für `security-admin`, TasmoFleet-Client mit Token Exchange, Anmeldeablauf mit zweitem Faktor. Keycloak: Client-Scope `write` mit Rollen-Zuordnung, Standard Token Exchange. authentik: eigener Provider für PMSS mit Federation zum TasmoFleet-Provider und Policy für `write`.
- [ ] Profilerzeugung aus Tasmota-Daten (GroupTopic1–4, FallbackTopic, MAC), Geräterollen `tf_role_dev_<mac>` (D-53).

### Phase 4 – Individuelle Zugangsdaten und Rechte einschränken

- [ ] Individuelle Tasmota-Zugangsdaten mit Rückfallpfad über HTTP.
- [ ] Weitere Geräte und Anwendungen schrittweise migrieren; Profile anwenden.
- [ ] Gemeinsamen Benutzer und `role_legacy` ablösen.
- [ ] Aufräumen: `pwfile`, Mount und alte Konfigurationszeilen entfernen, alte Backups und Log-Dateien der Beobachtung löschen (PMSS 9, Hinweis nach Phase 7).

## 10. Offene Fragen

1. **Backend-Auswahl:** ~~Manuell oder erkannt?~~ ✅ Entfällt: einziges Ziel ist Mosquitto mit DynSec über PMSS.
2. **Classic ACL – Integration:** Zurückgestellt (D-17).
3. **Dynamic Security – Zuständigkeit:** ✅ PMSS verwaltet nur Rollen und Gruppen mit Präfix `tf_` und gekennzeichnete Clients (D-14, PMSS v0.10).
4. **Client-Verwaltung:** Alle MQTT-Clients oder nur explizit registrierte?
5. **Identitäten:** ✅ Benutzername = Tasmota-Topic (D-15).
6. **Profile und Ausnahmen:** Welche Regeln gehören in Profile, wann sind Ausnahmen zulässig?
7. **Migration:** Automatisiert oder mit manueller Bestätigung je Client?
8. ~~**EMQX 5**~~ – Entfällt (D-26).
9. **Topic-Inventar:** ✅ Über Broker-Logs, eine Woche, zentraler Syslog-Dienst (Abschnitt 6.3).
10. **Betriebsgrenzen:** ✅ Soll-Zustand, Diff, Freigabe und Drift in TasmoFleet; Ist-Zustand, Schutz und Audit in PMSS; Sicherung beim Host (Abschnitt 7.3).
11. ~~**TLS-Pflicht mit Dynamic Security**~~ ✅ Geprüft (20.11.2026), umgesetzt in PMSS v0.7.
12. ~~**Rollen in TasmoFleet**~~ ✅ Beantwortet: `security-admin` (D-22).
13. ~~**Zielbroker**~~ ✅ Beantwortet: Mosquitto mit Dynamic Security, derzeit kein EMQX (D-26).
14. ~~**Token von TasmoFleet an PMSS**~~ ✅ **Entschieden (PMSS v0.12):** Benutzer-Token per Token Exchange (RFC 8693).
15. ~~**Passwörter in TasmoFleet:** Dauerhaft oder nur bis zur Übertragung?~~ ✅ **Entschieden (D-54):** nur bis zur erfolgreichen Übertragung auf das Gerät bzw. bis zum Abbruch; PMSS gibt ein erzeugtes Passwort nur einmal heraus (Frage 25).
16. ~~**Upstream-Interface:** Wie sieht das Interface in TasmoFleet aus, damit es nicht PMSS-spezifisch ist?~~ ✅ **Entschieden (PMSS v0.13):** TasmoFleet hängt von der Schnittstellenspezifikation „MQTT Security Service API v1“ ab; PMSS ist die Referenz-Implementierung (D-52, Abschnitt 5.4).

### Widersprüche zum PMSS-Dokument (seit v0.4)

17. ~~**Admin-Anmeldung am Port 8884**~~ ✅ **Entschieden (PMSS v0.7):** nur Zertifikat der eigenen Admin-CA, kein Passwort, Identitäten `pmss-admin` und `pmss-breakglass-admin`, Rolle `role_security_manager`.
18. ~~**Kann sich der Admin auch an Port 1883 anmelden?**~~ ✅ **Entschieden (PMSS v0.7):** Nein. Der Admin hat kein Passwort; der Bootstrap-Admin aus `dynsec init` wird gelöscht.
19. ~~**Wie viele Listener, und ist 1883 auf das IoT-Netz beschränkt?**~~ ✅ **Entschieden (PMSS v0.8):** 1883, 8883, 8885, 8884; Beschränkung per Firewall am Router (Abschnitt 7.1).
20. ~~**Lässt sich „TLS erforderlich“ pro Client durchsetzen?**~~ ✅ **Entschieden (PMSS v0.8):** Ja, als Zertifikats-Client ohne Passwort an 8885.
21. ~~**Rolle `security-admin` oder Scopes `read`/`write`?**~~ ✅ **Entschieden (PMSS v0.12):** PMSS prüft nur Scopes; der OIDC-Provider gibt `write` nur an `security-admin` aus. „Audit-Log lesend für `admin`“ betrifft das TasmoFleet-eigene Audit der Freigaben; PMSS hat keinen Audit-Endpunkt.
22. ~~**Woher kommt das Token, und wer prüft den zweiten Faktor?**~~ ✅ **Entschieden (PMSS v0.12):** TasmoFleet per Token Exchange; Administratoren per Device Authorization Grant; Service-Accounts in Produktion nur `read`. Der zweite Faktor wird nur im OIDC-Provider geprüft.
23. ~~**Wo liegen Diff, Freigabe, Sicherung, Drift-Report und Präfix-Prüfung?**~~ ✅ **Entschieden (PMSS v0.11):** Diff, Freigabe, Drift-Report und Sicherung vor dem Anwenden in TasmoFleet; PMSS liefert den Export, schützt nicht verwaltete Objekte, verlangt `If-Match` und protokolliert Vorher- und Nachher-Zustand; der Host sichert `dynamic-security.json` (Abschnitt 7.3).
24. ~~**Präfix `tf-` und Namenskonvention passen nicht zusammen.**~~ ✅ **Entschieden (PMSS v0.10):** Präfix `tf_` nur für Rollen und Gruppen; Clients behalten ihren Namen (Tasmota-Topic bzw. `CN=…`) und werden über `managed-by: pmss` in `textdescription` gekennzeichnet. `legacy-shared-user` und `role_legacy` bleiben unverwaltet. Nachfolger gesperrter Identitäten erhalten eine fortlaufende Nummer.
25. ~~**Wer erzeugt das Passwort?**~~ ✅ **Entschieden (PMSS v0.10):** Der Aufrufer kann ein Passwort mitgeben, sonst erzeugt PMSS eines und gibt es einmalig zurück. Format: genau 24 Zeichen `A–Z a–z 0–9`. `PUT …/password` wird zu `POST …/password`.
26. ~~**Erste Migration: kompatibel und klein oder neues Passwort für alle?**~~ ✅ **Entschieden (PMSS v0.9):** kompatibel; der Passwort-Hash wird übernommen, kein Gerät wird angefasst, `pwfile` bleibt als Rückfallweg.
27. ~~**Admin während der Übergangszeit im Klartext?**~~ ✅ **Entschieden (PMSS v0.7):** Listener 8884 vor der DynSec-Aktivierung, Ersteinrichtung offline.
28. ~~**Reihenfolge: Rechte einschränken vor oder nach PMSS?**~~ ✅ **Entschieden (PMSS v0.9):** Beobachten nach der ersten Migration (eine Woche), Einschränken erst mit individuellen Zugangsdaten nach PMSS.
29. ~~**Testbasis und API-Felder**~~ ✅ **Entschieden:** Testbasis Mosquitto 2.1.2 mit DynSec; ACL-Felder in der API: `allow` Pflicht, `priority` optional, Standard 0 (PMSS v0.11).
30. ⚠️ **Signierschlüssel für TasmoFleet: Zwischen-CA mit CRL oder eigene TasmoFleet-CA?** Vor der TasmoFleet-Ausbaustufe zu entscheiden.
    - Getestet (20.11.2026): Mosquitto prüft eine CRL nur für das Client-Zertifikat. Der Widerruf einer Zwischen-CA wirkt nicht; bei kompromittiertem Schlüssel müsste die App-CA getauscht werden.
    - Eigene TasmoFleet-CA: im Notfall aus `cafile` entfernen und neu starten (SIGHUP reicht nicht); erfordert zwei vertrauenswürdige CAs an 8885.
    - Zwischen-CA: Einzelne Zertifikate per CRL sperrbar; CRLs aller ausstellenden CAs müssen gepflegt werden. `nameConstraints` noch zu prüfen.
    - Vergleich im PMSS-Dokument, Abschnitt 5.4.
31. ~~**Identity Provider: nur Keycloak oder auch authentik?**~~ ✅ **Entschieden (24.11.2026):** Beide, weil TasmoFleet den Login mit Keycloak und mit authentik unterstützt. PMSS und die Spezifikation hängen von keinem bestimmten Provider ab (D-55, Spezifikation S-15); die Unterschiede regeln Spezifikation S-16/S-17 und PMSS T-8/T-9. Mindestversion authentik 2026.8.3 (Token Exchange ab 2026.8.0). Offen: zweiter Faktor mit authentik (App-Passwörter).

## 11. Architekturentscheidungen

| ID | Entscheidung | Status |
|---|---|---|
| D-01 | Gemeinsames fachliches Berechtigungsmodell | Für Review |
| D-02 | Mosquitto Classic ACL als Backend | Zurückgestellt (nur Ausgangszustand) |
| D-03 | Mosquitto Dynamic Security als Backend | ✅ Beschlossen (siehe D-26) |
| D-04 | Individuelle Zugangsdaten pro Tasmota-Gerät als mittelfristiges Ziel | Für Review |
| D-05 | Broker bleibt unabhängig vom TasmoFleet-Betrieb | Für Review |
| D-06 | Gemeinsamer fachlicher Testsatz (`mqtt-acl-verify`) | Für Review |
| D-07 | EMQX 5 architektonisch berücksichtigen | Zurückgestellt (D-26) |
| D-08 | MQTT-Clients unabhängig von Hersteller und Herkunft verwalten | Für Review |
| D-09 | Devices und Applications als Client-Kategorien | Für Review |
| D-10 | Wiederverwendbare Berechtigungsprofile | Für Review |
| D-11 | Individuelle Zugangsdaten auch für Applications | Für Review |
| D-12 | Tasmota-Regeln als spezialisiertes Profil | Für Review |
| D-13 | Docker-Anwendungen als eigenständige MQTT-Clients | Für Review |
| D-14 | Soll-Zustand mit Diff, Drift-Report, Präfix für verwaltete Objekte | ✅ Beschlossen: Präfix in PMSS (D-39), Diff und Drift in TasmoFleet (D-43) |
| D-15 | MQTT-Benutzername = Tasmota-Topic | ✅ Beschlossen (PMSS v0.10) |
| D-16 | Deny-by-default für alle Profile | Für Review (Umsetzung in DynSec geprüft) |
| D-17 | Classic ACL nur als Export | Zurückgestellt |
| D-18 | Regeln über die Client-ID sind keine Sicherheitsgrenze | Für Review |
| D-19 | Broker mit Listenern mit und ohne TLS: 1883, 8883, 8885, 8884 | ✅ Beschlossen (PMSS v0.8) |
| D-20 | Admin-Zugang nur über TLS, am Broker durchgesetzt | ✅ Beschlossen (PMSS v0.7, SEC-17) |
| D-21 | „TLS erforderlich“ pro Client = Anmeldung per App-Zertifikat ohne Passwort | ✅ Beschlossen (PMSS v0.8) |
| D-22 | Security-Funktionen nur für `security-admin`, zweiter Faktor über den OIDC-Provider | ✅ Beschlossen; umgesetzt im Provider (`write` nur für `security-admin`, bedingter Anmeldeablauf) |
| D-23 | Broker-Admin per Keycloak-Token am Broker | ❌ Ersetzt durch D-28 |
| D-24 | Notfall-Admin (Break-glass) per `mosquitto_ctrl` mit Zertifikat `pmss-breakglass-admin`, überwacht | ✅ Beschlossen (PMSS v0.7) |
| D-25 | Neue Zugangsdaten auf Geräte schreiben nur `security-admin` | ✅ Beschlossen |
| D-26 | Zielbroker Mosquitto mit Dynamic Security, derzeit kein EMQX | ✅ Beschlossen |
| D-27 | TasmoFleet verwaltet über die REST-API von PMSS, nicht direkt am Broker (Variante A) | ✅ Beschlossen; präzisiert durch D-52 |
| D-28 | PMSS-API akzeptiert nur Tokens, die Keycloak ausstellt | ❌ Ersetzt durch D-55 |
| D-29 | PMSS ist einziger DynSec-Admin, per Admin-Zertifikat am internen Listener 8884 | ✅ Beschlossen (PMSS v0.7) |
| D-30 | Erste Migration: gemeinsamer Bestandsbenutzer mit bisherigem Passwort (Hash übernommen), kompatible Rechte, danach einschränken | ✅ Beschlossen (PMSS v0.9) |
| D-31 | TasmoFleet ruft PMSS mit dem Token des Benutzers auf, per Token Exchange (RFC 8693) | ✅ Beschlossen (PMSS v0.12) |
| D-32 | Drei interne CAs: Server-CA, Admin-CA, App-CA; jeder Zertifikats-Listener vertraut genau einer Client-CA | ✅ Beschlossen (PMSS v0.7/v0.8) |
| D-33 | Admin-Rolle `role_security_manager` ersetzt die Rolle `admin` aus `dynsec init`; Sperren mit `deleteClient` | ✅ Beschlossen (PMSS v0.7) |
| D-34 | App-Listener mit `use_subject_as_username`; Namensregeln gegen Kollisionen | ✅ Beschlossen (PMSS v0.8) |
| D-35 | Externes Server-Zertifikat `mqtt.example.org`, Server-CA, RSA, 12 Monate, Erneuerung über `MqttFingerprint2` | ✅ Beschlossen (PMSS v0.8) |
| D-36 | App-Zertifikate vorerst manuell, später über TasmoFleet | ✅ Beschlossen (PMSS v0.8); Form des Signierschlüssels offen ⚠️ Frage 30 |
| D-37 | Legacy-Rolle: alles unter `#`, kein `$SYS/#`, kein `$CONTROL/#` | ✅ Beschlossen (PMSS v0.9) |
| D-38 | Beobachten (eine Woche, zentraler Syslog-Dienst) und Einschränken getrennt | ✅ Beschlossen (PMSS v0.9) |
| D-39 | PMSS verwaltet nur Rollen und Gruppen mit Präfix `tf_` und Clients mit `managed-by: pmss` in `textdescription`; Bestandsbenutzer und Legacy-Rolle bleiben unverwaltet | ✅ Beschlossen (PMSS v0.10) |
| D-40 | Gesperrte Admin- und App-Namen werden nicht wiederverwendet; Nachfolger mit fortlaufender Nummer | ✅ Beschlossen (PMSS v0.10) |
| D-41 | Passwort optional vom Aufrufer, sonst von PMSS erzeugt und einmalig zurückgegeben | ✅ Beschlossen (PMSS v0.10) |
| D-42 | MQTT-Passwörter: genau 24 Zeichen `A–Z a–z 0–9` | ✅ Beschlossen (PMSS v0.10) |
| D-43 | Soll-Zustand, Diff, Freigabe, Drift-Report und Sicherung vor dem Anwenden in TasmoFleet; PMSS ohne Zustand, Ist-Zustand über den Export (seit v0.9 `GET /api/v1/export`) | ✅ Beschlossen (PMSS v0.11) |
| D-44 | Host sichert `dynamic-security.json` regelmäßig | ✅ Beschlossen (PMSS v0.11) |
| D-45 | ACL-Liste einer Rolle per `PUT` als Ganzes ersetzen (`modifyRole`), mit eigener Validierung und Zurücklesen | ✅ Beschlossen (PMSS v0.11) |
| D-46 | `ETag`/`If-Match` für ändernde Aufrufe | ✅ Beschlossen (PMSS v0.11) |
| D-47 | Audit mit Vorher- und Nachher-Zustand, ohne Passwörter | ✅ Beschlossen (PMSS v0.11) |
| D-48 | PMSS prüft nur Scopes `read`/`write`; der OIDC-Provider gibt `write` nur an `security-admin` aus | ✅ Beschlossen (PMSS v0.12) |
| D-49 | Zweiter Faktor nur im OIDC-Provider, für alle Anmeldewege mit `write` | ✅ Beschlossen (PMSS v0.12) |
| D-50 | Keine Service-Accounts mit `write` in Produktion; Administratoren per Device Authorization Grant | ✅ Beschlossen (PMSS v0.12) |
| D-51 | Kein Audit-Endpunkt in PMSS; TasmoFleet führt das Audit der Freigaben | ✅ Beschlossen (PMSS v0.12) |
| D-52 | Schnittstellenspezifikation „MQTT Security Service API v1“ als Grundlage der Anbindung: TasmoFleet hängt von der Spezifikation ab, PMSS ist die Referenz-Implementierung; bei Abweichungen gilt die Spezifikation | ✅ Beschlossen (PMSS v0.13) |
| D-53 | GroupTopic, FallbackTopic und Discovery eines Tasmota-Geräts in einer eigenen Rolle `tf_role_dev_<mac>` (MAC klein, 12 Hex-Zeichen, Topic im `textname`) | ✅ Beschlossen (Spezifikation S-7, PMSS v0.13) |
| D-54 | TasmoFleet speichert MQTT-Passwörter nicht dauerhaft, sondern nur bis zur erfolgreichen Übertragung auf das Gerät bzw. bis zum Abbruch (Frage 15) | ✅ Beschlossen |
| D-55 | PMSS-API akzeptiert nur Tokens des konfigurierten OIDC-Providers, bei dem sich die Benutzer an TasmoFleet anmelden; getestet sind Keycloak und authentik (Frage 31) | ✅ Beschlossen (Spezifikation S-15, PMSS SEC-15) |
| D-56 | TasmoFleet fragt `write` nur für `security-admin` an, fällt bei Ablehnung einmal auf `read` zurück und wertet `scope` des getauschten Tokens aus | ✅ Beschlossen (Spezifikation S-16) |
| D-57 | Security Manager nur mit OIDC-Login in TasmoFleet; Tokens über dieselbe öffentliche URL wie der Login | ✅ Beschlossen (Spezifikation S-17, PMSS SEC-40) |

## 12. Anforderungen an TasmoFleet

Werden gesammelt und später als Feature-Issue bei hellwand/tasmofleet eingebracht.

- [ ] Neue Rolle `security-admin` aus dem bestehenden OIDC-Rollen-Claim, getrennt von `admin` und `operator`.
- [ ] Rechte pro Funktion nach der Rollenmatrix (Abschnitt 7.2).
- [ ] Rollen ohne Security-Recht sehen keine MQTT-Zugangsdaten.
- [ ] Felder „TLS-fähig“, „TLS erforderlich“ (= Zertifikats-Client) und „HTTP-Zugang verfügbar“ im Client-Objekt.
- [ ] Anbindung eines externen Security-Service nach der Schnittstellenspezifikation „MQTT Security Service API v1“ (REST mit OIDC-Token), ohne eigene Broker-Admin-Rechte und ohne Annahmen über PMSS hinaus.
- [ ] Security Manager nur im OIDC-Modus anbieten (`TASMOFLEET_AUTH_MODE=oidc`); im Header-Modus und mit lokalen Konten ausblenden (Spezifikation S-17).
- [ ] Vor dem ersten Export `GET /api/v1/info` lesen und `apiVersion` prüfen (Hauptversion 1); Präfixe, Kennzeichnung, Passwortregel und `limits.maxRequestBytes` aus der Antwort übernehmen statt fest einzubauen.
- [ ] Fehler nach `status` und `code` behandeln (`application/problem+json`, RFC 9457), nicht nach `title` oder `detail`.
- [ ] Gruppenzugehörigkeit über die Gruppe vergleichen und ändern: Sie gehört der Gruppe und geht nur in deren `ETag` ein, nicht in das des Clients.
- [ ] Je Client nur einen laufenden Passwortwechsel zulassen (ein Passwortwechsel ändert das `ETag` nicht).
- [ ] GroupTopic, FallbackTopic und Discovery je Gerät in einer Rolle `tf_role_dev_<mac>` anlegen (MAC in Kleinbuchstaben, 12 Hex-Zeichen, Topic im `textname`; D-53).
- [ ] Warnhinweise (`warnings`) aus den Antworten bei der Freigabe anzeigen.
- [ ] Benutzer-Token per Token Exchange (RFC 8693) beim selben OIDC-Provider gegen ein Token für den Security-Service tauschen (`aud` = Security-Service); TasmoFleet als vertraulicher Client. Ein gültiges Sitzungs-Token tauschen, vorher bei Bedarf erneuern; den Token-Endpunkt über dieselbe öffentliche URL wie der Login aufrufen (Spezifikation S-17).
- [ ] `write` nur für `security-admin` anfragen; lehnt der Provider ab, einmal nur mit `read` wiederholen; danach `scope` des getauschten Tokens auswerten und ändernde Funktionen nur mit `write` anbieten. Keycloak antwortet ohne `security-admin` mit `200` und `scope=read`, authentik lehnt die Anfrage mit `write` ab (Spezifikation S-16).
- [ ] Eigenes Audit der Freigaben (wer hat welchen Diff wann freigegeben), lesbar für `admin` und `security-admin`.
- [ ] Fingerprint des Server-Zertifikats auf Tasmota-Geräte mit TLS verteilen (`MqttFingerprint2` vor dem Wechsel, danach `MqttFingerprint1`).
- [ ] Später: App-Zertifikate ausstellen (Subject `/O=mqtt-apps/CN=<name>`, bei einer Zwischen-CA die Kette mitliefern), Schlüssel nur für `security-admin` nutzbar. Form des Schlüssels: Frage 30. Gesperrte Subjects kennen und nicht erneut vergeben (PMSS SEC-23).
- [ ] Geräte mit unzulässigem Topic blockieren: Topic beginnt mit `pmss-` oder enthält `=` bzw. `,` (Benutzername = Topic).
- [ ] Neue MQTT-Passwörter in der Regel von PMSS erzeugen lassen; nur bis zur Übertragung per `Backlog` vorhalten (D-54).
- [ ] Soll-Zustand gegen `GET /api/v1/export` vergleichen; Diff vor dem Anwenden `security-admin` zur Freigabe zeigen.
- [ ] Export vor dem Anwenden ablegen (Sicherung).
- [ ] Drift-Report: Abweichungen zwischen Soll und Export anzeigen, auch Änderungen per Break-glass.
- [ ] Bei Änderungen `If-Match` mit dem `ETag` aus dem Export senden; bei `412` neu einlesen und den Diff erneut zur Freigabe vorlegen.
- [ ] ACL-Listen einer Rolle als Ganzes per `PUT /api/v1/roles/{role}/acls` setzen; neue Rollen mit ACLs per `POST /api/v1/roles`.
- [x] Alle vier GroupTopics lesen, speichern und prüfen – #1005, in 0.42.0 umgesetzt.
- [ ] Ergebnis der Prüfung auf geteilte Topics in der Oberfläche anzeigen (Status und Liste der Kollisionen) – Folge-Issue zu #1005.

## 13. Zusammenfassung

Mosquitto bleibt der Broker (Produktion mit 2.1.4). Die Verwaltung über `password_file` und `acl_file` wird durch Dynamic Security ersetzt, zuerst manuell mit `mosquitto_ctrl` und danach über PMSS.

Die erste Migration ist klein und kompatibel: Der gemeinsame Bestandsbenutzer behält sein Passwort (der Hash wird übernommen) und erhält eine Legacy-Rolle ohne `$SYS` und `$CONTROL`. Kein Gerät wird angefasst; `pwfile` bleibt als Rückfallweg. Danach wird eine Woche lang das Topic-Inventar erfasst. Eingeschränkt wird erst mit individuellen Zugangsdaten nach PMSS.

PMSS ist der einzige Dienst mit Admin-Rechten am Broker. Er ist nur über eine HTTPS-REST-API erreichbar, die ausschließlich Tokens des OIDC-Providers akzeptiert (Keycloak oder authentik, derselbe wie beim Login an TasmoFleet), und spricht intern über Port 8884 mit dem Broker, angemeldet nur per Zertifikat der Admin-CA, ohne Passwort. Der Broker lehnt Admins an allen anderen Listenern ab.

Geräte und Anwendungen nutzen 1883 (IoT-Netz), 8883 (TLS mit Passwort) oder 8885 (nur App-Zertifikat). „TLS erforderlich“ ist am Broker nur für Zertifikats-Clients durchsetzbar.

TasmoFleet bietet die Oberfläche, kennt die Tasmota-Besonderheiten und verteilt neue Zugangsdaten und Fingerprints auf die Geräte. Rechte am Broker ändert es nur über die REST-API nach der Schnittstellenspezifikation „MQTT Security Service API v1“. PMSS ist deren Referenz-Implementierung; TasmoFleet hängt damit upstream nicht von PMSS ab.

Alle 13 Widersprüche aus v0.4 sind entschieden (17 bis 29), ebenso Frage 16 zum Upstream-Interface, Frage 15 zur Speicherung von Passwörtern (D-54) und Frage 31 zum Identity Provider (D-55). Offen sind noch die fachlichen Fragen 4, 6 und 7 zur Client-Verwaltung, zu Profilen und Ausnahmen und zum Ablauf der Migration, die mit dem TasmoFleet-Maintainer zu klären sind, sowie vor der TasmoFleet-Ausbaustufe die Form des TasmoFleet-Signierschlüssels (30).

PMSS prüft nur Scopes; der OIDC-Provider sorgt dafür, dass nur `security-admin` mit zweitem Faktor den Scope `write` erhält. TasmoFleet ruft PMSS mit einem getauschten Benutzer-Token auf, sodass das Audit von PMSS den echten Benutzer zeigt. Wie sich Keycloak und authentik dabei unterscheiden, fängt die Spezifikation mit festen Regeln für TasmoFleet ab.

Diff, Freigabe und Drift-Report liegen in TasmoFleet; PMSS bleibt ohne Zustand, liefert den Ist-Zustand, schützt nicht verwaltete Objekte und protokolliert jede Änderung mit Vorher- und Nachher-Zustand.

**Dieses Dokument ist ein Architekturentwurf für das Review.**

## 14. Übersicht der Widersprüche

| Frage | Thema | Overview | PMSS | Stand 20.11.2026 |
|---|---|---|---|---|
| 17 | Admin-Anmeldung 8884 | Nur Zertifikat | Zertifikat + Passwort (v0.6) | ✅ Nur Zertifikat, Admin-CA (PMSS v0.7) |
| 18 | Admin an 1883 | Abgelehnt | Möglich (v0.6) | ✅ Abgelehnt, Bootstrap-Admin gelöscht (PMSS v0.7) |
| 19 | Listener | Klartext, TLS, mTLS | 1883, 8884 (v0.6) | ✅ 1883, 8883, 8885, 8884 (PMSS v0.8) |
| 20 | „TLS erforderlich“ | Pro Client | Nicht abbildbar (v0.6) | ✅ Zertifikats-Client an 8885 (PMSS v0.8) |
| 21 | Autorisierung API | Rolle `security-admin` | Scopes `read`/`write` | ✅ Nur Scopes; `write` nur für `security-admin` über Keycloak (PMSS v0.12) |
| 22 | Token-Herkunft | Benutzer-Token / Token Exchange | Client Credentials, Device Grant | ✅ Token Exchange für TasmoFleet, Device Grant für Admins, 2FA nur in Keycloak (PMSS v0.12) |
| 23 | Diff, Freigabe, Drift, Sicherung | In PMSS | Nicht in API v1 (v0.6) | ✅ In TasmoFleet; PMSS liefert Export, `If-Match`, Audit (PMSS v0.11) |
| 24 | Präfix / Namen | `tf-`, Benutzer = Topic | `tasmota-001`, `role_tasmota` (v0.6) | ✅ `tf_` für Rollen/Gruppen, Kennzeichnung für Clients (PMSS v0.10) |
| 25 | Passworterzeugung | PMSS erzeugt | Aufrufer liefert (v0.6) | ✅ Optional Aufrufer, sonst PMSS; 24 Zeichen (PMSS v0.10) |
| 26 | Erste Migration | Kompatibel, schrittweise | Neues Passwort für alle (v0.6) | ✅ Kompatibel, Hash übernommen (PMSS v0.9) |
| 27 | Admin im Übergang | Nur TLS | Vor Phase 4 über 1883 (v0.6) | ✅ 8884 vor DynSec, Ersteinrichtung offline (PMSS v0.7) |
| 28 | Reihenfolge | Rechte vor PMSS | Rechte nach PMSS | ✅ Beobachten vorher, einschränken nachher (PMSS v0.9) |
| 29 | Testbasis / API-Felder | 2.0.18 Classic ACL | 2.1.2 DynSec | ✅ Testbasis; `allow` Pflicht, `priority` optional (PMSS v0.11) |
| 30 | Signierschlüssel TasmoFleet | – | Zwischen-CA mit CRL oder eigene CA | ⚠️ offen, vor der TasmoFleet-Ausbaustufe |

---

## Referenzen

- Schnittstellenspezifikation „MQTT Security Service API v1“ – `mqtt-security-service-api-v1` (aktuelle Fassung)
- TasmoFleet – `docs/mqtt-broker-acl.md`: https://github.com/hellwand/tasmofleet/blob/main/docs/mqtt-broker-acl.md
- TasmoFleet – Issue #1005 (alle vier GroupTopics): https://github.com/hellwand/tasmofleet/issues/1005
- Mosquitto Dynamic Security Plugin: https://mosquitto.org/documentation/dynamic-security/
- Eclipse Mosquitto – Dokumentation: https://mosquitto.org/documentation/
- Keycloak – Dokumentation: https://www.keycloak.org/documentation
- authentik – OAuth2-Provider und Token Exchange: https://docs.goauthentik.io/add-secure-apps/providers/oauth2/
- RFC 8693 – OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
- RFC 9457 – Problem Details for HTTP APIs: https://www.rfc-editor.org/rfc/rfc9457
- mqtt-acl-verify: https://github.com/Noschvie/mqtt-acl-verify (Test-Broker `testbroker-dynsec/`, `import-pwfile.py`, Doku `docs/testbroker-dynsec.md`)
- PMSS – Detaildokument `phylax-mqtt-security-service-design` (aktuelle Fassung): https://github.com/Noschvie/phylax-mqtt-security-service
