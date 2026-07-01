# Changelog

All notable changes to this project will be documented in this file.

## [v5.0.0]

### Added

- Added patterns for disabled syscollector integration tests. ([#546](https://github.com/wazuh/qa-integration-framework/pull/546))
- Added new SCA event patterns. ([#600](https://github.com/wazuh/qa-integration-framework/pull/600))
- Added new patterns for new SCA workflow. ([#464](https://github.com/wazuh/qa-integration-framework/pull/464))
- Added queue for req messages received in remoted simulator. ([#481](https://github.com/wazuh/qa-integration-framework/pull/481))
- Added support for agent internal limits in the ack startup. ([#579](https://github.com/wazuh/qa-integration-framework/pull/579))
- Added indexer block to make indexer-connector mandatory. ([#537](https://github.com/wazuh/qa-integration-framework/pull/537))
- Added bumper workflow for 5.X. ([#413](https://github.com/wazuh/qa-integration-framework/pull/413))
- Added workflow for automate the bump process in main. ([#391](https://github.com/wazuh/qa-integration-framework/pull/391))
- Added version file for package installation in default branch. ([#305](https://github.com/wazuh/qa-integration-framework/pull/305))
- Added `--set-as-main` flag support to repository bumper. ([#620](https://github.com/wazuh/qa-integration-framework/pull/620))
- Added support for running AWS integration tests on agent. ([#684](https://github.com/wazuh/qa-integration-framework/pull/684))

### Changed

- Adapted qa integration framework to new agent module startup. ([#595](https://github.com/wazuh/qa-integration-framework/pull/595))
- Migrated certificate generation to the `cryptography` API to keep up with pyOpenSSL 26.2.0 deprecations. ([#683](https://github.com/wazuh/qa-integration-framework/pull/683))
- Adapted Inventory patterns to use new sync protocol module. ([#468](https://github.com/wazuh/qa-integration-framework/pull/468))
- Adapted FIM patterns to use new sync protocol module. ([#440](https://github.com/wazuh/qa-integration-framework/pull/440))
- Renamed the usage of server to manager. ([#597](https://github.com/wazuh/qa-integration-framework/pull/597))
- Renamed config/log paths manager after separation. ([#576](https://github.com/wazuh/qa-integration-framework/pull/576))
- Modified all_disabled_ossec.conf file. ([#596](https://github.com/wazuh/qa-integration-framework/pull/596))
- Enabled cluster by default. ([#509](https://github.com/wazuh/qa-integration-framework/pull/509))
- Updated states persistence patterns and fixes. ([#465](https://github.com/wazuh/qa-integration-framework/pull/465))
- Demoted SCA and logcollector tests. ([#612](https://github.com/wazuh/qa-integration-framework/pull/612))
- Support manager naming changes. ([#592](https://github.com/wazuh/qa-integration-framework/pull/592))

### Removed

- Removed wazuh-execd from manager daemon lists. ([#585](https://github.com/wazuh/qa-integration-framework/pull/585))
- Removed Wazuh Manager deprecated daemons and CLI tools. ([#470](https://github.com/wazuh/qa-integration-framework/pull/470))
- Removed agent-auth references. ([#444](https://github.com/wazuh/qa-integration-framework/pull/444))
- Removed osquery references. ([#442](https://github.com/wazuh/qa-integration-framework/pull/442))
- Removed ciscat references. ([#443](https://github.com/wazuh/qa-integration-framework/pull/443))
- Removed use of deprecated `manage_agents` binary. ([#439](https://github.com/wazuh/qa-integration-framework/pull/439))
- Removed Tier 3 OS: Deprecate specials. ([#483](https://github.com/wazuh/qa-integration-framework/pull/483))
- Removed resources related to deprecated VD tests. ([#473](https://github.com/wazuh/qa-integration-framework/pull/473))
- Removed integrations from test coverage. ([#463](https://github.com/wazuh/qa-integration-framework/pull/463))
- Removed sca from remoted sent statistics. ([#523](https://github.com/wazuh/qa-integration-framework/pull/523))
- Removed default group from remoted_simulator STARTUP response. ([#589](https://github.com/wazuh/qa-integration-framework/pull/589))
- Removed syslog/labels from manager ITs. ([#602](https://github.com/wazuh/qa-integration-framework/pull/602))
- Removed references to 4.12.2 and updated changelog main. ([#379](https://github.com/wazuh/qa-integration-framework/pull/379))

### Fixed

- Fixed integration tests after ossec terminology removal. ([#611](https://github.com/wazuh/qa-integration-framework/pull/611))
- Fixed syscollector config pattern. ([#482](https://github.com/wazuh/qa-integration-framework/pull/482))
- Fixed Python unit test coverage script. ([#345](https://github.com/wazuh/qa-integration-framework/pull/345))
- Fixed server clean up minor issues. ([#615](https://github.com/wazuh/qa-integration-framework/pull/615))
- Increased net stop retries and force kill process as last resort. ([#621](https://github.com/wazuh/qa-integration-framework/pull/621))

## Prior versions

- [v4.14.5](https://github.com/wazuh/qa-integration-framework/blob/v4.14.5/CHANGELOG.md)
- [v4.14.4](https://github.com/wazuh/qa-integration-framework/blob/v4.14.4/CHANGELOG.md)
- [v4.14.3](https://github.com/wazuh/qa-integration-framework/blob/v4.14.3/CHANGELOG.md)
- [v4.14.2](https://github.com/wazuh/qa-integration-framework/blob/v4.14.2/CHANGELOG.md)
- [v4.14.1](https://github.com/wazuh/qa-integration-framework/blob/v4.14.1/CHANGELOG.md)
- [v4.14.0](https://github.com/wazuh/qa-integration-framework/blob/v4.14.0/CHANGELOG.md)
- [v4.13.1](https://github.com/wazuh/qa-integration-framework/blob/v4.13.1/CHANGELOG.md)
- [v4.13.0](https://github.com/wazuh/qa-integration-framework/blob/v4.13.0/CHANGELOG.md)

