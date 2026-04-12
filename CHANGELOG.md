# Changelog

All notable changes to the Paste Scanner Suite.

## [7.0.0] - 2026-04-12

### 🔥 Major Architectural Re-design
- **Unified Main Gateway**: The application is no longer a collection of loosely coupled scripts. All execution goes through `main.py` using mandatory `--mod1` or `--mod2` CLI flags to enforce architectural purity.
- **C-Level Extension Auto-Compilation**: To support Linux users out-of-the-box, running `main.py` now automatically detects if the `fast_utils` C library needs to be compiled. It verifies `gcc` and generates `fast_utils.so` on the fly. No manual makefiles needed!

### ✨ New Features
- **V2 Revision Tracking Capability (`--mod2`)**: The `proxy_scanner` now tracks content hashes of every URL. If an existing message changes under your nose in successive scans, it natively maps it as V2, V3 etc.
- **Deduplication Engine**: Global real-time duplicate skipping logic via memory map.
- **Mass Control Flag**: Added `--reset-all` to clear all dedup traces and history.

### 🧹 Cleanup 
- Fully scrubbed all Italian remnants from terminal output, help files, and logging syntax. The entire application is now localized purely to English.
- Eliminated terminal UI conflicts from argparse overrides.

---

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
