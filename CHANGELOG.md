# Changelog

All notable changes to Tor Clipboard Scanner.

## [6.0.4] - 2026-02-26

### ✨ New Features
- **Full Split-Screen UI**: Terminal takeover mode (`rich.Live screen=True`) fills 100% of window width and height — TOR column left, PROXIES column right
- **Proxy Randomization via `-b`**: The `--randomize` flag now shuffles the 16k+ proxy pool in addition to Tor exit nodes
- **Automated Install Script**: `setup.sh` installs Tor, creates a virtualenv, and installs Python dependencies automatically
- **Counter per Proxy**: Each proxy shows `PROXY [N/Total]` counter in the right column

### 🐛 Bug Fixes
- **Deadlock Fix**: Eliminated lock contention between proxy worker threads and `rich.Live` rendering loop. Introduced a dedicated `_auto_refresh` daemon thread that re-renders at 4fps without holding the data lock
- **Counter Bug**: `ProxyDisplayAdapter` was incrementing the global proxy counter on every log line instead of once per proxy — now correctly incremented at adapter creation time
- **Duplicate IP in Log**: Log lines no longer show the IP address twice (it's in the column header — no need to repeat it in every line)
- **rich.Live Assertion**: Fixed `AssertionError: refresh_per_second must be > 0` when starting the live display

### 📖 Upgrade Guide
```bash
git pull
source venv/bin/activate  # if using venv
python3 main.py -l -b
```

## [5.7.1] - 2026-02-05

### Added
- **Aggressive Recovery**: Script now performs a full Tor restart immediately after an IP verification failure.
- **Improved Statistics**: Report now includes total Tor restarts and total IP skips.
- **Infrastructure Tracking**: If an IP fails but succeeds after reset, it's no longer counted as a "failure" in final stats.

### Fixed
- **False Positive Change Detection**: Improved text normalization to ignore formatting/newline differences.
- **Node Filtering**: Better deduplication and exclusion of non-functional exit nodes.
- **Refined Logs**: Change detection now ignores transitions starting from or ending in an empty state.

## [5.7.0] - 2026-02-03

### 🔒 Dedicated Tor Instance (ZERO Impact on Other Apps)

Major architecture change: scanner now runs its OWN Tor daemon, completely isolated from system Tor.

### Added
- **Dedicated Tor Instance**: Scanner starts its own Tor on port 9060
  - System Tor (9050) NEVER touched - Simplex, browsers work normally
  - Auto-starts on script launch, auto-shuts down on exit
  - All data inside project folder (`data/scanner_tor/`)
- **Zero-Config Setup**: No password setup needed for new users
  - Uses cookie authentication for self-managed Tor
  - Works out of the box after `pip install`
- **Uninstall Command**: `python3 main.py --uninstall`
  - Removes all generated data
  - Shows folder removal command
- **Clean Data Command**: `python3 main.py --clean-data`
  - Removes logs, cache, scanner Tor data
  - Keeps project files intact

### Changed
- **Privacy**: ExitNodes settings only affect scanner's private Tor instance
- **Tor Recovery**: Aggressive "Hard Reset" strategy:
  - If IP verify fails -> Restart Torque daemon immediately -> Retry SAME IP
  - If fails again -> Skip
- Scanner Tor data moved from `~/.scanner_tor/` to `data/scanner_tor/`

### Fixed
- Rate limiting NEWNYM errors eliminated
- Other Tor apps never affected during scans

## [5.6.0] - 2026-02-01

### Added
- **Loop + Write Combination**: `-l` flag can now be used with write arguments (`-w`, `-tcf`, etc.)
  - Monitor changes AND write/overwrite in the same run
  - Useful for maintaining presence while detecting external changes
- **Global Change Detection**: `changes.txt` now updates in ALL modes, not just loop mode
  - Every scan compares with previous state
  - Automatic change logging regardless of flags used
- **Final Report on Exit**: Statistics summary now shown on both clean exit and Ctrl+C
  - Duration, failures, and totals displayed consistently

### Changed
- **Transient IP Verification**: IP verification status now disappears after completion (cleaner output)
- **Persistent Scan Logs**: Important events (Found, Removing, Overwriting) remain visible after completion
- **Improved Parallelism**: Direct threading implementation for guaranteed parallel execution
  - Both sites start within 0.002s of each other
  - Independent session management per site

### Fixed
- IP verification timeout increased to 25s for better reliability
- 5 fallback IP providers for robust verification

## [5.0.0] - 2026-01-03

### 🎉 Major Release - Fixed Current Files & Load from File

Critical bug fixes and new file loading feature.

### Fixed
- **CRITICAL: current_*.txt files now work correctly** 
  - Previous versions lost all data on each write
  - Now properly preserves existing IP data when updating
  - Correctly parses timestamp and content from existing entries
  - **NEW: Correctly reads multi-line content** - No longer truncates long messages
  - Files no longer show all IPs with empty content
- **Loop mode stability improved**
  - Fixed issue where content would be written then immediately removed
  - Better state management across iterations
  - More reliable change detection

### Added
- **Load messages from files**:
  - `-wf FILE` - Load message from file for both sites
  - `-tsf FILE` - Load from file for ssavr.com only
  - `-tcf FILE` - Load from file for copy-paste.online only
  - Useful for longer messages or automation
- **Simplified README** - More concise and easier to follow
- **Better error messages** when file loading fails

### Changed
- Help text simplified and reorganized
- Version bumped to 5.0.0 for major fixes

## [4.0.0] - 2024-12-22

### 🎉 Major Release - Enhanced Reliability & Deduplication

### Added
- **Retry Logic with Auto-Recovery**: Automatic 2 retries (3 total attempts) when encountering empty results
- **Smart Clean File Deduplication**: Tracks IP + content combinations to avoid duplicate logging
- **Enhanced Documentation**: Complete English documentation for public GitHub release

### Changed
- **All User-Facing Text to English**: Complete internationalization
- **Improved Clean File Logic**: Both clean files only log truly new content from others
- **Better Empty Detection**: Multiple retries before declaring field empty

### Fixed
- **copypaste_clean.txt Not Generating**: Fixed bug where file wasn't being created
- **False Positives in Changes File**: Retry logic prevents spurious changes
- **Duplicate Clean Entries**: Same content from same IP no longer logged multiple times

## [3.0.0] - 2024-12-20

### Added
- Secure password management with getpass
- Configuration file for settings
- Update checker with git integration
- Current state files for real-time IP tracking
- Statistics tracking for failures

## [2.0.0] - 2024-12-15

### Added
- Loop mode for continuous monitoring
- Change detection and logging
- Randomize IP order option
- Single IP scan mode
- Target-specific writing (-t, -ts, -tc options)

## [1.0.0] - 2024-12-10

### Added
- Initial release
- Basic scanning through Tor
- Read/write for both sites

---

## Upgrade Guide

### From 4.x to 5.0

**IMPORTANT**: Delete old current_*.txt files to start fresh with fixed format.

```bash
rm data/current_ssavr.txt data/current_copypaste.txt
git pull origin main
python3 scanner.py
```

Your configuration and logs are preserved.

### From 3.x to 4.0

No breaking changes - simply update:
```bash
git pull origin main
python3 scanner.py
```

---

**Note**: Version numbers follow [Semantic Versioning](https://semver.org/).

### 🎉 Major Release - Enhanced Reliability & Deduplication

This release focuses on eliminating false positives and preventing duplicate logging.

### Added
- **Retry Logic with Auto-Recovery**: Automatic 2 retries (3 total attempts) when encountering empty results
  - 2-second delay between retries to allow connection stabilization
  - Visual feedback: `(empty, retry 1/2)... (empty, retry 2/2)...`
  - Applies to both ssavr.com and copy-paste.online
  - Significantly reduces false empty results from connection issues
- **Smart Clean File Deduplication**: 
  - Loads existing clean file content at startup into memory cache
  - Tracks IP + content combinations to avoid duplicate logging
  - Only logs new content or same content on different IPs
  - Shows `💾 Already logged in clean file, skipping` when skipping duplicates
- **Enhanced Documentation**: Complete English documentation for public GitHub release
  - Detailed README with all features and examples
  - Clear explanation of quote requirements in command arguments
  - Comprehensive troubleshooting guide

### Changed
- **All User-Facing Text to English**: Complete internationalization for wider audience
  - Console output, error messages, help text
  - Status messages and progress indicators
  - All documentation and examples
- **Improved Clean File Logic**: 
  - `copypaste_clean.txt` now fully functional and working correctly
  - Both clean files only log truly new content from others
  - Better filtering of own messages vs external content
- **Better Empty Detection**: 
  - Multiple retries before declaring field empty
  - Reduces false change detections in loop mode
  - More reliable state tracking

### Fixed
- **copypaste_clean.txt Not Generating**: Fixed bug where copy-paste clean file wasn't being created
- **False Positives in Changes File**: Retry logic prevents spurious empty↔content changes
- **Duplicate Clean Entries**: Same content from same IP no longer logged multiple times
- **Connection Timeout False Empties**: Retry system handles temporary network issues

### Technical Improvements
- Optimized cache loading from existing clean files
- Better IP extraction from various text formats
- Enhanced error handling in read operations
- Improved text normalization and comparison

## [3.0.0] - 2024-12-20

### Added
- Secure password management with getpass
- Configuration file for storing settings
- Update checker with git integration
- Current state files for real-time IP tracking
- Advanced text processing features (can be disabled)
- Statistics tracking for failures
- Debug logging system

### Changed
- Reorganized file structure (data/ directory)
- Improved error messages and user feedback
- Better IP verification system
- Enhanced session management

### Fixed
- IP verification reliability
- Session cookie handling
- Rate limiting issues with copy-paste.online

## [2.0.0] - 2024-12-15

### Added
- Loop mode for continuous monitoring
- Change detection and logging
- Randomize IP order option
- Single IP scan mode
- Message history management
- Target-specific writing (-t, -ts, -tc options)

### Changed
- Complete rewrite of scanning logic
- Improved Tor integration
- Better exit node selection

## [1.0.0] - 2024-12-10

### Added
- Initial release
- Basic scanning through Tor exit nodes
- Read and write functionality for both sites
- Simple logging system
- History tracking

---

## Upgrade Guide

### From 3.x to 4.0

No breaking changes. Simply update and run:

```bash
git pull origin main
python3 scanner.py
```

Your existing:
- Configuration files will work unchanged
- Message history will be preserved  
- Log files will continue to append
- Clean files will be loaded into cache automatically

New features are automatic - just enjoy improved reliability!

### From 2.x to 3.0

- Password will be requested on first run (saved to config if desired)
- Files reorganized into `data/` directory - old logs can be moved manually
- New `data/.tor_scanner_config.json` stores settings

### From 1.x to 2.0

Major rewrite - recommend fresh install:

```bash
git pull origin main
rm -rf *.txt *.json  # Backup first if needed
python3 scanner.py
```

---

**Note**: Dates are in YYYY-MM-DD format. Version numbers follow [Semantic Versioning](https://semver.org/).
