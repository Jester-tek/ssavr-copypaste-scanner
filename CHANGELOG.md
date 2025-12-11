# Changelog

All notable changes to this project will be documented in this file.

## [3.0.0] - 2024-12-10

### 🔴 CRITICAL FIXES

**Session Persistence Bug (MAJOR):**
- **Fixed HTTP session reuse causing cookie/TCP persistence across different IPs**
  - This was causing the "23 user agents" ban on copy-paste.online
  - This was causing "phantom reads" where script saw content from previous IP
  - Now creates fresh `requests.Session()` for each exit node change
  - Eliminates cookie contamination and TCP socket reuse

**IP Detection & Verification:**
- **Fixed IP detection**: Now uses exit node IP directly + external verification
  - Implements polling system to verify IP change (up to 30s timeout)
  - Uses `ifconfig.co/ip` to confirm actual external IP
  - Solves ssavr.com showing wrong IPs (255.x.x.x)
  - More reliable and consistent IP tracking

**Index Bug:**
- **Fixed -i index**: Now correctly 1-based (e.g., `-i 139` starts from IP #139, not #140)
- Fixed enumerate logic to match user expectations

**Text Comparison:**
- **Fixed content comparison**: Now uses `clean_text()` for all comparisons
  - Removes soft hyphens, zero-width chars before comparison
  - Prevents false "content changed" detections
  - Consistent ownership detection

### ✅ NEW FEATURES

- **Single IP mode** (`-s` flag): Scan only one specific IP and stop
  - Example: `python3 scanner.py -s 139` scans only exit node #139
  - Cannot be combined with `-i`, `-l`, or `-b`

- **Configurable Tor ports**: `--socks-port` and `--control-port`
  - Allows using Tor Browser (ports 9150/9151) instead of system Tor
  - Example: `python3 scanner.py --socks-port 9150 --control-port 9151`

- **StrictNodes enforcement**: Forces Tor to use exact exit node or fail
  - Prevents Tor from falling back to alternative nodes
  - Guarantees IP consistency

- **IPv6 support**: Robust IP extraction supporting both IPv4 and IPv6
  - Uses `ipaddress` module for validation
  - Handles dual-stack configurations

- **Debug logging**: New `data/debug.log` file
  - Logs anomalies (non-200 responses, rate limits, exceptions)
  - Includes response headers and body snippets
  - Helps diagnose site-specific issues

- **Rate limit detection**: Automatically detects and logs anti-abuse messages
  - Warns when copy-paste.online shows user-agent limit
  - Logs to debug file for analysis

### 🔧 TECHNICAL IMPROVEMENTS

- **Simplified marker disable**: Just create empty file `data/.disable_advanced_features`
  - No more SHA256 hash requirement
  - Simple `os.path.exists()` check

- **Improved retry logic**: Better handling of empty reads and failures
  - Polls with delays between retries
  - Distinguishes between empty content and connection failures

- **Better error messages**: More descriptive validation errors

- **1-second delay between sites**: Reduces rate limit triggers

### 📝 DOCUMENTATION

- Updated README with:
  - Tor Browser mode usage
  - How to disable text normalization
  - IP verification polling explanation
  - Debug logging location

### 🐛 BUG FIXES SUMMARY

1. ✅ Session reuse → Fresh session per exit node
2. ✅ Cookie persistence → Cleared with each new session
3. ✅ TCP keep-alive → New socket per exit node
4. ✅ IP mismatches → Polling verification system
5. ✅ Index off-by-one → Proper 1-based indexing
6. ✅ Text comparison → Clean text normalization
7. ✅ Marker disable → Simplified file check

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
- **Retry logic for reads**: Automatically retries reading if content is empty or request fails
  - Prevents false "content disappeared" logs due to temporary loading issues
  - Retries up to 2 times with 2-second delays
  - Significantly reduces false positives in change detection
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
