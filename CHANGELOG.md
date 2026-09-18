# Changelog

All notable changes to this project will be documented in this file.

## [v5.0.0]

### Added

| Issue | Comment |
|-------|---------|
| [#546](https://github.com/wazuh/qa-integration-framework/pull/546) | Added patterns for disabled syscollector integration tests. |
| [#600](https://github.com/wazuh/qa-integration-framework/pull/600) | Added new SCA event patterns. |
| [#464](https://github.com/wazuh/qa-integration-framework/pull/464) | Added new patterns for new SCA workflow. |
| [#481](https://github.com/wazuh/qa-integration-framework/pull/481) | Added queue for req messages received in remoted simulator. |
| [#579](https://github.com/wazuh/qa-integration-framework/pull/579) | Added support for agent internal limits in the ack startup. |
| [#537](https://github.com/wazuh/qa-integration-framework/pull/537) | Added indexer block to make indexer-connector mandatory. |
| [#413](https://github.com/wazuh/qa-integration-framework/pull/413) | Added bumper workflow for 5.X. |
| [#391](https://github.com/wazuh/qa-integration-framework/pull/391) | Added workflow for automate the bump process in main. |
| [#305](https://github.com/wazuh/qa-integration-framework/pull/305) | Added version file for package installation in default branch. |
| [#620](https://github.com/wazuh/qa-integration-framework/pull/620) | Added `--set-as-main` flag support to repository bumper. |
| [#684](https://github.com/wazuh/qa-integration-framework/pull/684) | Added support for running AWS integration tests on agent. |
| [#822](https://github.com/wazuh/qa-integration-framework/pull/822) | Added HTTPS agent-manager protocol support: TLS HTTP server, AES-CMAC request authentication, and updated simulators/patterns/templates. |
| [#840](https://github.com/wazuh/qa-integration-framework/pull/840) | Added reverse-proxy `prefix` support to `RemotedSimulator`, so it can route requests under the manager's default `/wazuh-manager/` prefix (or a custom one) instead of only bare root. |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added SPKI pin helpers (`spki_sha256`, `spki_pin`, `spki_pin_hex`, `load_certificate`) usable without a running simulator, and exposed the certificate the listener actually presents as `tls_certificate_pem` / `tls_pin` / `tls_pin_hex`, so a token can be minted from the served certificate instead of a hardcoded pin that rots |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added `GET /cacerts` to `RemotedSimulator`, plus an opt-in `use_bootstrap_chain` certificate topology in which the certificate that route serves is the CA signing the listener's own, so an agent can pin the fetched CA and then reconnect verified against it |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added `wazuh_testing.utils.enrollment_token`, a codec for the agent enrollment token, and `RemotedSimulator.mint_enrollment_token()` to mint one for a live instance |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added `wazuh_testing.tools.bootstrap_client`, a reference client that walks the whole enrollment-token bootstrap from a token alone |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added SubjectAlternativeName-capable CA and leaf certificate helpers to `wazuh_testing.tools.https_server` |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added `wazuh_testing.utils.jwt_enroll`, the whole `wazuh-enroll+jwt` bearer profile: signing, verification, `peek_kid()` and the three HKDF key derivations (shared password, enrollment token, re-enrollment secret), pinned by the product's own frozen test vectors |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | `RemotedSimulator` now authenticates `POST /enroll` and can answer with any of the eight 401 classes (`unknown_agent`, `stale_token`, `invalid_signature`, `invalid_request`, `enrollment_key_unavailable`, `token_unknown`, `token_expired`, `token_revoked`), each with its RFC 6750 §3 `WWW-Authenticate` challenge and `/enroll`'s nested error envelope |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | `RemotedSimulator` issues and rotates per-agent re-enrollment secrets: `issue_reenroll_secret`, `set_reenroll_secret()`, `reenroll_secret_for()` and `register_enrollment_token()`, so a test can seed both halves of an already-enrolled identity |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Added authd's `403` verdicts on an enrollment token to `ENROLL_FORCED_ERRORS` (`authd_token_not_found`/9022, `authd_token_expired`/9023, `authd_token_exhausted`/9024), and `AGENT_REENROLL_SECRET_PATH` to the configuration path constants |

### Changed

| Issue | Comment |
|-------|---------|
| [#595](https://github.com/wazuh/qa-integration-framework/pull/595) | Adapted qa integration framework to new agent module startup. |
| [#683](https://github.com/wazuh/qa-integration-framework/pull/683) | Migrated certificate generation to the `cryptography` API to keep up with pyOpenSSL 26.2.0 deprecations. |
| [#468](https://github.com/wazuh/qa-integration-framework/pull/468) | Adapted Inventory patterns to use new sync protocol module. |
| [#440](https://github.com/wazuh/qa-integration-framework/pull/440) | Adapted FIM patterns to use new sync protocol module. |
| [#597](https://github.com/wazuh/qa-integration-framework/pull/597) | Renamed the usage of server to manager. |
| [#576](https://github.com/wazuh/qa-integration-framework/pull/576) | Renamed config/log paths manager after separation. |
| [#596](https://github.com/wazuh/qa-integration-framework/pull/596) | Modified all_disabled_ossec.conf file. |
| [#509](https://github.com/wazuh/qa-integration-framework/pull/509) | Enabled cluster by default. |
| [#465](https://github.com/wazuh/qa-integration-framework/pull/465) | Updated states persistence patterns and fixes. |
| [#612](https://github.com/wazuh/qa-integration-framework/pull/612) | Demoted SCA and logcollector tests. |
| [#592](https://github.com/wazuh/qa-integration-framework/pull/592) | Support manager naming changes. |
| [#783](https://github.com/wazuh/qa-integration-framework/pull/783) | Updated the analysisd statistics template to the engine metrics dump format. |
| [#790](https://github.com/wazuh/qa-integration-framework/pull/790) | Updated the agent analysisd statistics template to the engine metrics dump format. |
| [#834](https://github.com/wazuh/qa-integration-framework/pull/834) | Updated the manager socket constants to the standardized `queue/sockets` layout. |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Declared `cryptography` explicitly; four modules import it directly and it was only arriving transitively through `pyOpenSSL` |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | `TLSHTTPServer` now terminates TLS per accepted connection rather than wrapping its listening socket, and `RemotedSimulator.certificate_controller` is built on first use instead of in the constructor |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | `mode='REJECT_AUTH'` now answers `unknown_agent` rather than a class-less 401, so the suites that use it to force a re-enrollment keep working now that a class-less 401 no longer makes the agent discard its identity |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | An unsupported `protocol-version` on `/enroll` is answered with `400` instead of `401`: it is not a credential failure, and conflating them hides which of the two the agent got wrong |
| [#39284](https://github.com/wazuh/wazuh/issues/39284) | The default API password is resolved instead of assumed: `login()`, `set_authorization_header()` and `get_api_details_dict()` take it from `WAZUH_API_PASSWORD` in the environment, and only fall back to the historical literal, which still applies to a 4.x manager. A 5.x manager ships no password for its default users, so the value is whatever provisioned the node, and the integration workflow exports it. Resolution happens at call time rather than as a default argument, since the environment is provisioned after this module is imported |

### Removed

| Issue | Comment |
|-------|---------|
| [#585](https://github.com/wazuh/qa-integration-framework/pull/585) | Removed wazuh-execd from manager daemon lists. |
| [#835](https://github.com/wazuh/qa-integration-framework/pull/835) | Removed `wazuh-manager-monitord` from the manager daemon list. |
| [#834](https://github.com/wazuh/qa-integration-framework/pull/834) | Removed the socket constants for sockets the manager no longer creates. |
| [#470](https://github.com/wazuh/qa-integration-framework/pull/470) | Removed Wazuh Manager deprecated daemons and CLI tools. |
| [#444](https://github.com/wazuh/qa-integration-framework/pull/444) | Removed agent-auth references. |
| [#442](https://github.com/wazuh/qa-integration-framework/pull/442) | Removed osquery references. |
| [#443](https://github.com/wazuh/qa-integration-framework/pull/443) | Removed ciscat references. |
| [#439](https://github.com/wazuh/qa-integration-framework/pull/439) | Removed use of deprecated `manage_agents` binary. |
| [#483](https://github.com/wazuh/qa-integration-framework/pull/483) | Removed Tier 3 OS: Deprecate specials. |
| [#473](https://github.com/wazuh/qa-integration-framework/pull/473) | Removed resources related to deprecated VD tests. |
| [#463](https://github.com/wazuh/qa-integration-framework/pull/463) | Removed integrations from test coverage. |
| [#523](https://github.com/wazuh/qa-integration-framework/pull/523) | Removed sca from remoted sent statistics. |
| [#589](https://github.com/wazuh/qa-integration-framework/pull/589) | Removed default group from remoted_simulator STARTUP response. |
| [#602](https://github.com/wazuh/qa-integration-framework/pull/602) | Removed syslog/labels from manager ITs. |
| [#379](https://github.com/wazuh/qa-integration-framework/pull/379) | Removed references to 4.12.2 and updated changelog main. |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Removed the four `*_enroll_*` AES-CMAC helpers from `wazuh_testing.utils.request_auth`. They spoke the `Authorization: WazuhEnroll <ts>:<mac>` scheme that wazuh/wazuh#38582 removed from the agent, so `RemotedSimulator` was authenticating `/enroll` a whole scheme behind the product |

### Fixed

| Issue | Comment |
|-------|---------|
| [#611](https://github.com/wazuh/qa-integration-framework/pull/611) | Fixed integration tests after ossec terminology removal. |
| [#482](https://github.com/wazuh/qa-integration-framework/pull/482) | Fixed syscollector config pattern. |
| [#345](https://github.com/wazuh/qa-integration-framework/pull/345) | Fixed Python unit test coverage script. |
| [#615](https://github.com/wazuh/qa-integration-framework/pull/615) | Fixed server clean up minor issues. |
| [#621](https://github.com/wazuh/qa-integration-framework/pull/621) | Increased net stop retries and force kill process as last resort. |
| [#39063](https://github.com/wazuh/wazuh/issues/39063) | Failed TLS handshakes are recorded in `handshake_failures` instead of being discarded; they were reaching `socketserver`'s `except OSError` and never surfacing, leaving a client that refused the served certificate with no server-side trace |

## Prior versions

- [v4.14.7](https://github.com/wazuh/qa-integration-framework/blob/v4.14.7/CHANGELOG.md)
- [v4.14.6](https://github.com/wazuh/qa-integration-framework/blob/v4.14.6/CHANGELOG.md)
- [v4.14.5](https://github.com/wazuh/qa-integration-framework/blob/v4.14.5/CHANGELOG.md)
- [v4.14.4](https://github.com/wazuh/qa-integration-framework/blob/v4.14.4/CHANGELOG.md)
- [v4.14.3](https://github.com/wazuh/qa-integration-framework/blob/v4.14.3/CHANGELOG.md)
- [v4.14.2](https://github.com/wazuh/qa-integration-framework/blob/v4.14.2/CHANGELOG.md)
- [v4.14.1](https://github.com/wazuh/qa-integration-framework/blob/v4.14.1/CHANGELOG.md)
- [v4.14.0](https://github.com/wazuh/qa-integration-framework/blob/v4.14.0/CHANGELOG.md)
- [v4.13.1](https://github.com/wazuh/qa-integration-framework/blob/v4.13.1/CHANGELOG.md)
- [v4.13.0](https://github.com/wazuh/qa-integration-framework/blob/v4.13.0/CHANGELOG.md)
