# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2024-12-10

### Major Changes
- **Complete file reorganization**: 
  - Frequently accessed files (`ssavr_clean.txt`, `copypaste_clean.txt`, `changes.txt`) stay in main directory
  - All other files (detailed logs, config, state) moved to `data/` directory
- **Fixed copy-paste.online rate limiting**: Now uses single consistent user agent to avoid "51 user-agents" error
- **Fixed current state files**: Completely rewritten logic to avoid duplication and corruption
  - Files now properly track IPs even as exit nodes change
  - No more repeated "Last updated:" entries
  - Clean, readable format maintained across updates

### Added
- Auto-update system (`-u` flag): Check for updates from GitHub while preserving all data
- Current state snapshots in `data/` directory showing latest content per IP
- Persistent loop mode that survives restarts
- Better change detection in loop mode
- Improved text processing for cross-platform compatibility

### Changed
- User agent strategy: ssavr.com uses rotating agents, copy-paste.online uses single agent
- Password setup instructions clarified (plain text vs hash)
- All configuration and logs now in `data/` directory for better organization
- Version bumped to 2.0.0 for major reorganization

### Fixed
- Copy-paste.online "51 user-agents" rate limit error
- Current state files corruption and duplication
- Loop mode state tracking across IP changes
- File organization for better user experience

## [1.0.0] - 2024-12-08

### Initial Release
- Scan ssavr.com and copy-paste.online through Tor exit nodes
- Write messages to empty fields or overwrite own messages
- Loop mode for continuous monitoring
- Detailed and clean log files
- Message history tracking
- Statistics on failures
- Random IP order support
- Selective site targeting
