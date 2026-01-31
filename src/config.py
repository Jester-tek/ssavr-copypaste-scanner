import os
import json
from pathlib import Path

# Version and Info
VERSION = "5.5.0"
REPO_URL = "https://github.com/Jester-tek/ssavr-copypaste-scanner"

# Directory Structure
BASE_DIR = Path.cwd()
DATA_DIR = BASE_DIR / "data"

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

# Files
CONFIG_FILE = DATA_DIR / ".tor_scanner_config.json"
HISTORY_FILE = DATA_DIR / "inputs_history.json"
CURRENT_STATE_FILE = DATA_DIR / "current_state.json"
DEBUG_LOG = DATA_DIR / "debug.log"

SSAVR_CLEAN = "ssavr_clean.txt"
COPYPASTE_CLEAN = "copypaste_clean.txt"
CHANGES_FILE = "changes.txt"

SSAVR_DETAILED = DATA_DIR / "ssavr_detailed.txt"
COPYPASTE_DETAILED = DATA_DIR / "copypaste_detailed.txt"
CURRENT_SSAVR = DATA_DIR / "current_ssavr.txt"
CURRENT_COPYPASTE = DATA_DIR / "current_copypaste.txt"

# Feature Flags
DISABLE_MARKER_FILE = DATA_DIR / ".disable_advanced_features"
MARKER_ENABLED = not DISABLE_MARKER_FILE.exists()

# Tor Configuration
DEFAULT_SOCKS_PORT = 9050
DEFAULT_CONTROL_PORT = 9051

# Performance / Timeouts
TOR_CONNECT_TIMEOUT = 25  # Seconds to wait for Tor IP verification
SITE_READ_TIMEOUT = 15    # Seconds to wait for website
SITE_RETRY_DELAY = 1      # Seconds between retries
IP_STABILIZATION_DELAY = 0.5 # Wait before requests after IP change

def load_config():
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
