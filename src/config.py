import os
import json
from pathlib import Path

# Version and Info
VERSION = "5.8.0"
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
AIRFORSHARE_CLEAN = "airforshare_clean.txt"
CHANGES_FILE = "changes.txt"

SSAVR_DETAILED = DATA_DIR / "ssavr_detailed.txt"
COPYPASTE_DETAILED = DATA_DIR / "copypaste_detailed.txt"
AIRFORSHARE_DETAILED = DATA_DIR / "airforshare_detailed.txt"
CURRENT_SSAVR = DATA_DIR / "current_ssavr.txt"
CURRENT_COPYPASTE = DATA_DIR / "current_copypaste.txt"
CURRENT_AIRFORSHARE = DATA_DIR / "current_airforshare.txt"

# Feature Flags
DISABLE_MARKER_FILE = DATA_DIR / ".disable_advanced_features"
MARKER_ENABLED = not DISABLE_MARKER_FILE.exists()

# Tor Configuration - SYSTEM (used by other apps - DO NOT TOUCH)
SYSTEM_SOCKS_PORT = 9050
SYSTEM_CONTROL_PORT = 9051

# Tor Configuration - SCANNER (dedicated instance, no impact on other apps)
SCANNER_SOCKS_PORT = 9060
SCANNER_CONTROL_PORT = 9061
SCANNER_TOR_DIR = DATA_DIR / "scanner_tor"  # Inside project folder
SCANNER_TORRC = SCANNER_TOR_DIR / "torrc"
SCANNER_TOR_DATA = SCANNER_TOR_DIR / "data"

# Backwards compatibility
DEFAULT_SOCKS_PORT = SCANNER_SOCKS_PORT
DEFAULT_CONTROL_PORT = SCANNER_CONTROL_PORT

# Performance / Timeouts
TOR_CONNECT_TIMEOUT = 25  # Seconds to wait for Tor IP verification
SITE_READ_TIMEOUT = 3
SITE_WRITE_TIMEOUT = 5  # Seconds to wait for website
SITE_RETRY_DELAY = 1      # Seconds between retries
IP_STABILIZATION_DELAY = 0.5 # Wait before requests after IP change

# Proxy Engine Configuration
PROXY_SOURCES = [
    # TheSpeedX (main + SOCKS-List mirror)
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    # Proxifly
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt",
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
    # ProxyGenerator (pre-verified stable)
    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/MostStable/socks5.txt",
    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/Stable/http.txt",
    "https://raw.githubusercontent.com/proxygenerator1/ProxyGenerator/main/Stable/socks5.txt",
    # dpangestuw
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/socks5_proxies.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/allive.txt",
    # komutan234
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    # officialputuid
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/xResults/Proxies.txt",
    # vmheaven
    "https://raw.githubusercontent.com/vmheaven/VMHeaven-Free-Proxy-Updated/main/all_proxies.txt",
    # proxyscrape
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
    # monosans
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    # hookzof + ShiftyTR
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    # roosterkid
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
]
PROXY_THREAD_COUNT = 300 # Number of concurrent proxy requests
PROXY_CONNECT_TIMEOUT = 12 # Seconds to wait for a free proxy to connect

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
