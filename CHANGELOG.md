# Changelog

All notable changes to Tor Clipboard Scanner will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] - 2024-12-22

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
