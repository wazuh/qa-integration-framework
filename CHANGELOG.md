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

### Changed

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Declared `cryptography` explicitly; four modules import it directly and it was only arriving transitively through `pyOpenSSL` |
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | `TLSHTTPServer` now terminates TLS per accepted connection rather than wrapping its listening socket, and `RemotedSimulator.certificate_controller` is built on first use instead of in the constructor |

### Removed

| Issue | Comment |
|-------|---------|

### Fixed

| Issue | Comment |
|-------|---------|
| [#39021](https://github.com/wazuh/wazuh/issues/39021) | Failed TLS handshakes are recorded in `handshake_failures` instead of being discarded; they were reaching `socketserver`'s `except OSError` and never surfacing, leaving a client that refused the served certificate with no server-side trace |

## Prior versions

- [v5.0.1](https://github.com/wazuh/qa-integration-framework/blob/v5.0.1/CHANGELOG.md)
- [v5.0.0](https://github.com/wazuh/qa-integration-framework/blob/v5.0.0/CHANGELOG.md)
