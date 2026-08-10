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

### Removed

| Issue | Comment |
|-------|---------|
| [#585](https://github.com/wazuh/qa-integration-framework/pull/585) | Removed wazuh-execd from manager daemon lists. |
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

### Fixed

| Issue | Comment |
|-------|---------|
| [#611](https://github.com/wazuh/qa-integration-framework/pull/611) | Fixed integration tests after ossec terminology removal. |
| [#482](https://github.com/wazuh/qa-integration-framework/pull/482) | Fixed syscollector config pattern. |
| [#345](https://github.com/wazuh/qa-integration-framework/pull/345) | Fixed Python unit test coverage script. |
| [#615](https://github.com/wazuh/qa-integration-framework/pull/615) | Fixed server clean up minor issues. |
| [#621](https://github.com/wazuh/qa-integration-framework/pull/621) | Increased net stop retries and force kill process as last resort. |

## Prior versions

- [v4.14.5](https://github.com/wazuh/qa-integration-framework/blob/v4.14.5/CHANGELOG.md)
- [v4.14.4](https://github.com/wazuh/qa-integration-framework/blob/v4.14.4/CHANGELOG.md)
- [v4.14.3](https://github.com/wazuh/qa-integration-framework/blob/v4.14.3/CHANGELOG.md)
- [v4.14.2](https://github.com/wazuh/qa-integration-framework/blob/v4.14.2/CHANGELOG.md)
- [v4.14.1](https://github.com/wazuh/qa-integration-framework/blob/v4.14.1/CHANGELOG.md)
- [v4.14.0](https://github.com/wazuh/qa-integration-framework/blob/v4.14.0/CHANGELOG.md)
- [v4.13.1](https://github.com/wazuh/qa-integration-framework/blob/v4.13.1/CHANGELOG.md)
- [v4.13.0](https://github.com/wazuh/qa-integration-framework/blob/v4.13.0/CHANGELOG.md)
