# Phylax MQTT Security Service

A REST API service for managing Mosquitto Dynamic Security clients, roles and access control.

**Status:** design phase. The service is not implemented yet.

So far this repository contains:

- [Keycloak integration test](test/integration/keycloak/README.md) – checks scopes, audience, the role mapping of scope `write` and Standard Token Exchange against Keycloak 26.8.2.

Broker-side tests (Mosquitto 2.1.2 with Dynamic Security) live in [mqtt-acl-verify](https://github.com/Noschvie/mqtt-acl-verify).

## License

[GNU Affero General Public License v3.0 or later](LICENSE) (`AGPL-3.0-or-later`).
