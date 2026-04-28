# Changelog

All notable changes to this project will be documented in this file.

## [5.0.0]

### Added
- Test entry for automated merge test [5538]

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

### Changed

- Adapted qa integration framework to new agent module startup. ([#595](https://github.com/wazuh/qa-integration-framework/pull/595))
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

## [4.14.1]

## [4.14.0]

### Added
- Test entry for automated merge test [5538]

- Added integration tests for syscollector browser extensions. ([#450](https://github.com/wazuh/qa-integration-framework/pull/450))

### Fixed

- Fixed syscollector users and groups tests. ([#400](https://github.com/wazuh/qa-integration-framework/pull/400))

## [4.13.1]

## [4.13.0]

### Added
- Test entry for automated merge test [5538]

- Added missing ruleset files in the ossec.conf. ([#380](https://github.com/wazuh/qa-integration-framework/pull/380))

## [4.12.0]

### Added
- Test entry for automated merge test [5538]

- Added a script to parse pytest results. ([#283](https://github.com/wazuh/qa-integration-framework/pull/283))

## [4.11.2]

## [4.11.1]

### Changed

- Updated the `ERROR_BIND_PORT` message due to agent connectivity improvements. ([#311](https://github.com/wazuh/qa-integration-framework/pull/311))

## [4.11.0]

## [4.10.1]

## [4.10.0]

### Added
- Test entry for automated merge test [5538]
- Added a script and dependencies to get the Python unit tests coverage. ([#254](https://github.com/wazuh/qa-integration-framework/pull/254))

## [4.9.2]

## [4.9.1]

## [4.9.0]

### Added
- Test entry for automated merge test [5538]
- Added `/manager/configuration` endpoint route constant. ([#63](https://github.com/wazuh/qa-integration-framework/pull/63))
- Added support for the `enrollment` integration tests. ([#123](https://github.com/wazuh/qa-integration-framework/pull/123))
- Added support for the `wazuh-logcollector` integration tests. ([#122](https://github.com/wazuh/qa-integration-framework/pull/122))
- Added patterns for inotify and max eps cases in the FIM integration tests. ([#119](https://github.com/wazuh/qa-integration-framework/pull/119))
- Added support for the `integratord` integration tests. ([#118](https://github.com/wazuh/qa-integration-framework/pull/118))
- Added support for `logtest` and `remoted` integration tests. ([#102](https://github.com/wazuh/qa-integration-framework/pull/102))
- Added AWS module related functions and data generation methods. ([#25](https://github.com/wazuh/qa-integration-framework/pull/25))

### Changed
- Updated the API script file name. ([#154](https://github.com/wazuh/qa-integration-framework/pull/154))

### Fixed
- Fixed bug in the service control function for Windows agents. ([#121](https://github.com/wazuh/qa-integration-framework/pull/121))
- Fixed bug in the RemotedSimulator udp connections mocker. ([#86](https://github.com/wazuh/qa-integration-framework/pull/86))
- Fixed agent_simulator response for active-response configuration commands. ([#139](https://github.com/wazuh/qa-integration-framework/pull/139))

## [4.8.2]

## [4.8.1]

## [4.8.0]

### Added
- Test entry for automated merge test [5538]
- Added the `/manager/configuration` endpoint route constant. ([#131](https://github.com/wazuh/qa-integration-framework/pull/131))

### Changed
- Updated name of the `vulnerability-detection` configuration block in the `all_disabled_ossec.conf` file. ([#51](https://github.com/wazuh/qa-integration-framework/pull/51))
- Updated the `wazuh-db_template.json` to remove vulnerability detector fields. ([#89](https://github.com/wazuh/qa-integration-framework/pull/89))

## [4.7.5]

## [4.7.4]

## [4.7.3]

## [4.7.2]

## [4.7.1]
