# Changelog

All notable changes to this project will be documented in this file.

## [v5.1.0]

### Added

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added `GET /cacerts` to `RemotedSimulator`, plus an opt-in `use_bootstrap_chain` certificate topology in which the certificate that route serves is the CA signing the listener's own, so an agent can pin the fetched CA and then reconnect verified against it |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added `wazuh_testing.utils.enrollment_token`, a codec for the agent enrollment token, and `RemotedSimulator.mint_enrollment_token()` to mint one for a live instance |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added `wazuh_testing.tools.bootstrap_client`, a reference client that walks the whole enrollment-token bootstrap from a token alone |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added SubjectAlternativeName-capable CA and leaf certificate helpers to `wazuh_testing.tools.https_server` |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added `wazuh_testing.utils.jwt_enroll`, the whole `wazuh-enroll+jwt` bearer profile: signing, verification, `peek_kid()` and the three HKDF key derivations (shared password, enrollment token, re-enrollment secret), pinned by the product's own frozen test vectors |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | `RemotedSimulator` now authenticates `POST /enroll` and can answer with any of the eight 401 classes (`unknown_agent`, `stale_token`, `invalid_signature`, `invalid_request`, `enrollment_key_unavailable`, `token_unknown`, `token_expired`, `token_revoked`), each with its RFC 6750 §3 `WWW-Authenticate` challenge and `/enroll`'s nested error envelope |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | `RemotedSimulator` issues and rotates per-agent re-enrollment secrets: `issue_reenroll_secret`, `set_reenroll_secret()`, `reenroll_secret_for()` and `register_enrollment_token()`, so a test can seed both halves of an already-enrolled identity |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Added authd's `403` verdicts on an enrollment token to `ENROLL_FORCED_ERRORS` (`authd_token_not_found`/9022, `authd_token_expired`/9023, `authd_token_exhausted`/9024), and `AGENT_REENROLL_SECRET_PATH` to the configuration path constants |

### Changed

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Declared `cryptography` explicitly; four modules import it directly and it was only arriving transitively through `pyOpenSSL` |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | `TLSHTTPServer` now terminates TLS per accepted connection rather than wrapping its listening socket, and `RemotedSimulator.certificate_controller` is built on first use instead of in the constructor |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | `mode='REJECT_AUTH'` now answers `unknown_agent` rather than a class-less 401, so the suites that use it to force a re-enrollment keep working now that a class-less 401 no longer makes the agent discard its identity |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | An unsupported `protocol-version` on `/enroll` is answered with `400` instead of `401`: it is not a credential failure, and conflating them hides which of the two the agent got wrong |

### Removed

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Removed the four `*_enroll_*` AES-CMAC helpers from `wazuh_testing.utils.request_auth`. They spoke the `Authorization: WazuhEnroll <ts>:<mac>` scheme that wazuh/wazuh#38582 removed from the agent, so `RemotedSimulator` was authenticating `/enroll` a whole scheme behind the product |

### Fixed

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Failed TLS handshakes are recorded in `handshake_failures` instead of being discarded; they were reaching `socketserver`'s `except OSError` and never surfacing, leaving a client that refused the served certificate with no server-side trace |

## Prior versions

- [v5.0.1](https://github.com/wazuh/qa-integration-framework/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/qa-integration-framework/blob/v5.0.0/CHANGELOG.md)
