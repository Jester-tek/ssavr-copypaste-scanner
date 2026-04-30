#!/usr/bin/env python3
"""
URL Brute-Forcer — Sequentially scans URLs on cl1p.net, justpaste.it, rentry.co
Finds content left by other users, saves to clean files.
Supports: resume, write mode, automatic proxy rotation, rate-limit detection.
V2 revision tracking: if a URL's content changes between scans, appends as V2/V3/etc.
"""
import os
import sys
import json
import time
import signal
import hashlib
import argparse
import threading
from datetime import datetime
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sites.cl1p_api import Cl1pAPIClient
from src.sites.justpaste_api import JustPasteClient
from src.sites.rentry_api import RentryClient
from src.proxy_manager import ProxyManager
from src import config, utils

# ─── Constants ────────────────────────────────────────────────────────────────



VERSION = "1.1.0"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
STATE_FILE = Path("data/url_forcer_state.json")
HISTORY_FILE = Path("data/url_forcer_history.json")
URL_HISTORY_FILE = Path("data/url_content_history.json")

# Output files (root directory)
CL1P_RESULTS = Path("cl1p_clean.txt")
JUSTPASTE_RESULTS = Path("justpaste_clean.txt")
RENTRY_RESULTS = Path("rentry_clean.txt")
CL1P_KEYS_FILE = Path("data/cl1p_keys.txt")

# ─── Fast C Extensions ───────────────────────────────────────────────────────
import ctypes
import re

try:
    _fast = ctypes.CDLL(str(Path(__file__).parent / "fast_utils.so"))
    _fast.is_foreign_content.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _fast.is_foreign_content.restype = ctypes.c_int
    _fast.index_to_string.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
    _fast.index_to_string.restype = None
    _ext_loaded = True
except Exception as e:
    _ext_loaded = False


# ─── URL Generator ───────────────────────────────────────────────────────────

def index_to_string(index, charset=CHARSET):
    """Convert a sequential index to a string combination."""
    if _ext_loaded:
        buf = ctypes.create_string_buffer(32)
        _fast.index_to_string(ctypes.c_uint64(index), buf)
        return buf.value.decode("ascii")
        
    base = len(charset)
    length = 1
    total_before = 0
    block_size = base
    while index >= total_before + block_size:
        total_before += block_size
        length += 1
        block_size *= base

    remaining = index - total_before
    result = []
    for _ in range(length):
        result.append(charset[remaining % base])
        remaining //= base
    return "".join(reversed(result))


def string_to_index(s, charset=CHARSET):
    """Convert a string back to its sequential index."""
    base = len(charset)
    length = len(s)
    total_before = 0
    for l in range(1, length):
        total_before += base ** l
    position = 0
    for char in s:
        position = position * base + charset.index(char)
    return total_before + position


# ─── Content Filter (anti-foreign-script) ────────────────────────────────────

FOREIGN_REGEX = re.compile(
    r'[\u0600-\u06FF\u0400-\u04FF\u4E00-\u9FFF\u3040-\u30FF\uAC00-\uD7A3'
    r'\u0E00-\u0E7F\u0590-\u05FF\u0900-\u097F\u0B80-\u0BFF]'
)
LATIN_REGEX = re.compile(r'[a-zA-Z0-9\u00C0-\u024F]')

def get_foreign_chars(text):
    """Return all characters in the text that trigger the foreign filter."""
    m = FOREIGN_REGEX.findall(text)
    return "".join(m)

def is_foreign_content(text, threshold=50):
    """Ratio-based filter: skip only if more than threshold% of readable
    characters are in foreign scripts. This allows aesthetic bios with
    a few decorative kanji/symbols to pass through while blocking walls
    of Arabic/Russian/Chinese text.
    
    Uses C extension when available for speed, falls back to Python regex."""
    if _ext_loaded:
        text_bytes = text.encode("utf-8", errors="ignore")
        return _fast.is_foreign_content(text_bytes, threshold) == 1
    
    foreign = len(FOREIGN_REGEX.findall(text))
    latin = len(LATIN_REGEX.findall(text))
    total = foreign + latin
    if total < 10:
        return False  # too short to judge
    return (foreign * 100 // total) > threshold


# ─── URL Content History (V2 Revision Tracking) ─────────────────────────────

class URLContentHistory:
    """Tracks content hashes per URL to detect changes across scans.
    Stores {url_path: [hash1, hash2, ...]} where each hash represents a version.
    Everything stays in RAM; flushed to disk on save() or Ctrl+C."""

    def __init__(self):
        self._data = {}  # {url_path: [hash1, hash2, ...]}
        self._lock = threading.Lock()
        self._dirty = False
        self._load()

    def _load(self):
        if URL_HISTORY_FILE.exists():
            try:
                with open(URL_HISTORY_FILE, "r") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}

    def save(self):
        """Flush to disk (called on shutdown / periodic save)."""
        with self._lock:
            if not self._dirty:
                return
            URL_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(URL_HISTORY_FILE, "w") as f:
                    json.dump(self._data, f)
                self._dirty = False
            except Exception:
                pass

    def get_version(self, site_prefix, url_path, content_hash):
        """Check if this URL+hash combo is known.
        Returns:
            0  = brand new URL, never seen
            -1 = URL seen before, same content hash (duplicate, skip)
            N  = URL seen before, NEW content hash; N is the version number (2, 3, ...)
        """
        key = f"{site_prefix}:{url_path}"
        with self._lock:
            if key not in self._data:
                return 0
            hashes = self._data[key]
            if content_hash in hashes:
                return -1  # same content, skip
            return len(hashes) + 1  # next version

    def register(self, site_prefix, url_path, content_hash):
        """Register a URL+hash pair."""
        key = f"{site_prefix}:{url_path}"
        with self._lock:
            if key not in self._data:
                self._data[key] = []
            if content_hash not in self._data[key]:
                self._data[key].append(content_hash)
                self._dirty = True


# ─── Results Writer ──────────────────────────────────────────────────────────

class ResultsWriter:
    """Writes results in a clean, readable format. Deduplicates by content.
    Supports V2 revision tracking for changed URLs."""

    def __init__(self, filepath, filter_enabled=False):
        self.filepath = filepath
        self.filter_enabled = filter_enabled
        self.lock = threading.Lock()
        self.count = 0
        self.foreign_skipped = 0
        self.duplicate_skipped = 0
        self.header_len = 150
        self._seen_hashes = set()
        self._dedup_file = Path(str(filepath).replace(".txt", "_dedup.json"))
        self._load_dedup()

    def _load_dedup(self):
        """Load previously seen content hashes from disk."""
        if self._dedup_file.exists():
            try:
                with open(self._dedup_file, "r") as f:
                    self._seen_hashes = set(json.load(f))
            except Exception:
                self._seen_hashes = set()

    def _save_dedup(self):
        """Persist dedup hashes to disk (called inside lock)."""
        try:
            self._dedup_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._dedup_file, "w") as f:
                json.dump(list(self._seen_hashes), f)
        except Exception:
            pass

    def _init_header(self):
        """Initialize or read the file header with skip stats."""
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        if not self.filepath.exists():
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(self._format_header() + "\n")
        else:
            with open(self.filepath, "r+", encoding="utf-8") as f:
                line = f.readline()
                if line.startswith("[ LOG ]"):
                    import re
                    m_for = re.search(r"foreign skipped\):\s*(\d+)", line)
                    m_dup = re.search(r"duplicates skipped\):\s*(\d+)", line)
                    if m_for: self.foreign_skipped = int(m_for.group(1))
                    if m_dup: self.duplicate_skipped = int(m_dup.group(1))

    def _format_header(self):
        tmpl = "[ LOG ] Skipped (foreign skipped): {:07d} | Skipped (duplicates skipped): {:07d} "
        return tmpl.format(self.foreign_skipped, self.duplicate_skipped).ljust(self.header_len)

    def _update_header_safe(self):
        """Safely rewrite header at top of file (assumes lock is held)."""
        if self.filepath.exists():
            try:
                with open(self.filepath, "r+", encoding="utf-8") as f:
                    f.seek(0)
                    f.write(self._format_header() + "\n")
            except Exception:
                pass

    def record_skip(self, reason):
        """Record a skipped file and update the file header in real-time."""
        with self.lock:
            if reason == "foreign":
                self.foreign_skipped += 1
            elif reason == "duplicate":
                self.duplicate_skipped += 1
            self._update_header_safe()

    def _hash(self, content):
        return hashlib.sha256(content.strip().lower().encode("utf-8")).hexdigest()

    def is_duplicate(self, content):
        """Return True if this exact content has already been saved."""
        with self.lock:
            return self._hash(content) in self._seen_hashes

    def save(self, site_name, url_path, full_url, content, title=None, version=0):
        """Save a found result to the output file, skipping duplicates and foreign languages.
        version=0 means first time, version>=2 means V2/V3/etc."""
        # Create header if needed
        if self.count == 0 and not self.filepath.exists():
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write(self._format_header() + "\n")

        # Foreign script filter (ratio-based: skip if >50% foreign) — only when --filter is active
        if self.filter_enabled and is_foreign_content(content, threshold=50):
            self.record_skip("foreign")
            return "foreign"
        
        h = self._hash(content)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            if h in self._seen_hashes:
                return False  # duplicate, don't save
            self._seen_hashes.add(h)
            self.count += 1
            clean_url = full_url.replace("https://", "").replace("http://", "")
            
            # Build URL label (with version tag if applicable)
            url_label = clean_url
            if version >= 2:
                url_label = f"{clean_url} V{version}"
            
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(f"\n======================================================================\n")
                f.write(f"URL: {url_label}\n")
                f.write(f"Timestamp: {timestamp}\n")
                if title:
                    f.write(f"Title: {title}\n")
                f.write(f"--- CONTENT ---\n")
                f.write(f"{content}\n")
                f.write(f"======================================================================\n\n")
            # Persist hashes every 50 saves
            if self.count % 50 == 0:
                self._save_dedup()
            return True

    def flush_dedup(self):
        """Force-save dedup index to disk."""
        with self.lock:
            self._save_dedup()

    def get_count(self):
        with self.lock:
            return self.count


# ─── Message History ─────────────────────────────────────────────────────────

class MessageHistory:
    """Tracks written messages so they aren't counted as 'found'."""

    def __init__(self):
        self.messages = set()
        self._load()

    def _load(self):
        if HISTORY_FILE.exists():
            try:
                with open(HISTORY_FILE, "r") as f:
                    data = json.load(f)
                    self.messages = set(data.get("messages", []))
            except:
                pass

    def save(self):
        HISTORY_FILE.parent.mkdir(exist_ok=True)
        with open(HISTORY_FILE, "w") as f:
            json.dump({"messages": list(self.messages)}, f, indent=2)

    def add(self, msg):
        self.messages.add(msg.strip())
        self.save()

    def is_mine(self, content):
        """Check if content matches a message we previously wrote."""
        clean = content.strip()
        return clean in self.messages


# ─── Main Forcer ─────────────────────────────────────────────────────────────

class PasteScanner:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.mode = args.mode
        self.write_msg = self._load_write_message()
        self.quiet_ui = getattr(args, 'quiet_ui', False)
        self.filter_enabled = getattr(args, 'filter', False)
        
        # Special handling for target="all"
        if self.target == "all":
            self.running = True
            return
            
        # Load cl1p API tokens
        self.cl1p_tokens = self._load_cl1p_tokens()
        self.token_idx = 0
        self.token_lock = threading.Lock()
        
        try:
            import src.secrets as secret_cfg
            primary_token = getattr(secret_cfg, 'CL1P_API_TOKEN', "")
        except ImportError:
            primary_token = getattr(config, 'CL1P_API_TOKEN', "")
            
        if not self.cl1p_tokens and primary_token:
            self.cl1p_tokens = [primary_token]
            
        if self.target == "cl1p":
            self.workers = 2500  # Match other scanners - cl1p API is lightweight
            self.using_proxies = True # FORCED PROXIES due to 100% IP ban on cl1p
            self.site_timeout = 5  # Increased for proxy handshake
        elif self.target == "rentry":
            self.workers = config.MOD2_PROXY_THREAD_COUNT
            self.using_proxies = True
            self.site_timeout = 8  # Extra time for SOCKS proxy handshake
        else:  # justpaste
            self.workers = config.MOD2_PROXY_THREAD_COUNT
            self.using_proxies = True
            self.site_timeout = 8  # Extra time for SOCKS proxy handshake

        self.running = True

        # Stats
        self.stats = {
            "checked": 0,
            "hits": 0,
            "duplicates": 0,
            "foreign_skipped": 0,
            "empty": 0,
            "errors": 0,
            "wrote": 0,
            "wrote_fake": 0,
            "skipped_mine": 0,
            "proxies_rotated": 0,
            "revisions": 0,
        }
        self.stats_lock = threading.Lock()
        self.start_time = time.time()

        # Components
        self.history = MessageHistory()
        self.url_history = URLContentHistory()
        self.proxy_mgr = None

        # Thread local storage for isolated clients
        self.thread_local = threading.local()

        # Config sites
        if self.target == "cl1p":
            self.site_url = "https://cl1p.net"
            self.results = ResultsWriter(CL1P_RESULTS, filter_enabled=self.filter_enabled)
        elif self.target == "rentry":
            self.site_url = "https://rentry.co"
            self.results = ResultsWriter(RENTRY_RESULTS, filter_enabled=self.filter_enabled)
        else:
            self.site_url = "https://justpaste.it"
            self.results = ResultsWriter(JUSTPASTE_RESULTS, filter_enabled=self.filter_enabled)

        self.results._init_header()

        # Count existing results in file asynchronously to avoid blocking supervisor
        if self.results.filepath.exists():
            def _count():
                try:
                    count_separators = 0
                    with open(self.results.filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("======================================================================"):
                                count_separators += 1
                    self.results.count = count_separators // 2
                except Exception:
                    pass
            threading.Thread(target=_count, daemon=True).start()

        # Register write message in history
        if self.write_msg:
            self.history.add(self.write_msg)

        # Load state (resume point)
        self.state = self._load_state()
        state_key = f"{self.target}_{self.mode}"
        self.current_idx = self.state.get(state_key, 0)

        # Signal handler
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _load_cl1p_tokens(self):
        """Load multiple cl1p API tokens from file for rotation."""
        tokens = []
        if CL1P_KEYS_FILE.exists():
            try:
                with open(CL1P_KEYS_FILE, "r") as f:
                    for line in f:
                        t = line.strip()
                        if t and not t.startswith("#"):
                            tokens.append(t)
            except Exception as e:
                print(f"  ⚠️ Error loading cl1p keys: {e}")
        return tokens

    def _load_write_message(self):
        """Load write message from args (which were already populated from file loading in main)."""
        if self.mode != "write":
            return None
        # Only allow writing on cl1p
        if self.target == "cl1p":
            return getattr(self.args, "write", None)
        return None

    def _load_state(self):
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    data = json.load(f)
                # Load retry queue if it exists for this target
                retry_key = f"{self.target}_{self.mode}_retry"
                self.retry_queue = deque(data.get(retry_key, []))
                if self.retry_queue and not self.quiet_ui:
                    print(f"  🔄 Loaded {len(self.retry_queue)} URLs from retry queue")
                return data
            except:
                pass
        self.retry_queue = deque()
        return {}

    def _save_state(self):
        state_key = f"{self.target}_{self.mode}"
        self.state[state_key] = self.current_idx
        
        # Persist retry queue so failed URLs survive restarts
        retry_key = f"{self.target}_{self.mode}_retry"
        self.state[retry_key] = list(getattr(self, 'retry_queue', deque()))
        
        STATE_FILE.parent.mkdir(exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(self.state, f, indent=2)

    def _handle_interrupt(self, sig, frame):
        self.running = False
        # Flush everything to disk immediately
        self._save_state()
        self.results.flush_dedup()
        self.url_history.save()

    def _enable_proxies(self):
        """Activate proxy rotation."""
        if self.proxy_mgr is not None:
            return
        print("\n  🔄 Activating proxy rotation...")
        self.proxy_mgr = ProxyManager()
        self.proxy_mgr.fetch_proxies()
        self.proxy_mgr.start_auto_refresh(interval_mins=30)
        if self.proxy_mgr.proxies_list:
            self.using_proxies = True
            print(f"  ✓ {len(self.proxy_mgr.proxies_list)} proxies loaded\n")
        else:
            print("  ✗ No proxies found, continuing with direct IP\n")

    def _get_worker_client(self):
        """Returns an isolated HTTP client for the current thread."""
        if not hasattr(self.thread_local, "client"):
            if self.target == "cl1p":
                # Token rotation: assign a token to this worker
                with self.token_lock:
                    if not self.cl1p_tokens:
                        token = ""
                    else:
                        token = self.cl1p_tokens[self.token_idx % len(self.cl1p_tokens)]
                        self.token_idx += 1
                c = Cl1pAPIClient(token)
            elif self.target == "rentry":
                c = RentryClient()
            else:
                c = JustPasteClient()
            
            if self.using_proxies and self.proxy_mgr:
                self._rotate_worker_proxy(c)
                
            self.thread_local.client = c
        return self.thread_local.client

    def _rotate_worker_proxy(self, client):
        """Assign a new rotated proxy to the current thread's client."""
        if not self.proxy_mgr:
            return
            
        proxy = self.proxy_mgr.get_next_proxy()
        if proxy:
            client.current_proxy = proxy['address']
            proxy_dict = self.proxy_mgr.get_requests_dict(proxy)

            def proxy_session():
                s = __import__("requests").Session()
                s.proxies = proxy_dict
                s.timeout = 5  # Safety net: default timeout for all requests through proxy
                return s

            client.reset_session()
            client.session_factory = proxy_session
            with self.stats_lock:
                self.stats["proxies_rotated"] += 1

    # ── Worker ────────────────────────────────────────────────────────────

    def _process_url(self, idx):
        """Process a single URL. Returns a status dict."""
        url_str = index_to_string(idx)
        full_url = f"{self.site_url}/{url_str}"
        result = {"idx": idx, "url": url_str, "status": "empty", "content_len": 0, "content": ""}

        client = self._get_worker_client()

        if self.mode == "write":
            return self._process_write(client, url_str, full_url, result)
        else:
            return self._process_read(client, url_str, full_url, result)

    def _process_read(self, client, url_str, full_url, result):
        """Read-only mode: check if URL has content with auto-retry on proxy fails."""
        max_retries = 2
        
        for attempt in range(max_retries):
            content = client.read(url_str)

            if client.is_rate_limited or content is None:
                if self.using_proxies and self.proxy_mgr:
                    if client.current_proxy:
                        self.proxy_mgr.mark_failure(client.current_proxy)
                    self._rotate_worker_proxy(client)
                continue

            if not content:
                result["status"] = "empty"
                return result

            if self.history.is_mine(content):
                result["status"] = "mine"
                return result

            # V2 revision tracking
            content_hash = hashlib.sha256(content.strip().lower().encode("utf-8")).hexdigest()
            version = self.url_history.get_version(self.target, url_str, content_hash)

            if version == -1:
                result["status"] = "duplicate"
                return result

            # Register this URL+hash
            self.url_history.register(self.target, url_str, content_hash)

            if self.results.is_duplicate(content):
                self.results.record_skip("duplicate")
                result["status"] = "duplicate"
                return result

            result["status"] = "hit"
            result["content_len"] = len(content)
            if not self.quiet_ui:
                result["content"] = content

            title = getattr(client, 'last_title', None)
            save_result = self.results.save(self.target, url_str, full_url, content, title, version=version)
            if save_result == "foreign":
                result["status"] = "foreign"
            elif version >= 2:
                result["status"] = "revision"
            return result
            
        result["status"] = "error"
        return result

    def _process_write(self, client, url_str, full_url, result):
        """Write mode: check first, save if content exists, then write with auto-retry."""
        max_retries = 2
        
        for attempt in range(max_retries):
            existing = client.read(url_str)
            
            if client.is_rate_limited or existing is None:
                if self.using_proxies and self.proxy_mgr:
                    if client.current_proxy:
                        self.proxy_mgr.mark_failure(client.current_proxy)
                    self._rotate_worker_proxy(client)
                continue

            # Decide whether to write content
            should_write = False
            
            if existing:
                if not self.history.is_mine(existing) and not self.results.is_duplicate(existing):
                    # V2 revision tracking for write mode too
                    content_hash = hashlib.sha256(existing.strip().lower().encode("utf-8")).hexdigest()
                    version = self.url_history.get_version(self.target, url_str, content_hash)
                    
                    if version != -1:
                        self.url_history.register(self.target, url_str, content_hash)
                        result["status"] = "hit+write"
                        result["content_len"] = len(existing)
                        result["content"] = existing
                        self.results.save(self.target, url_str, full_url, existing, title=getattr(client, 'last_title', None), version=version)
                    else:
                        result["status"] = "occupied"
                else:
                    if self.history.is_mine(existing):
                        result["status"] = "mine"
                    else:
                        result["status"] = "duplicate"
            else:
                should_write = True

            # Write our message
            if should_write:
                if self.target == "cl1p":
                    content_to_write = utils.normalize_text_output(self.write_msg)
                    wrote = client.write(url_str, content_to_write)
                    # cl1p API rejects bodies > ~940 chars with 400
                    if wrote == 'too_long' and len(content_to_write) > 900:
                        content_to_write = content_to_write[:900].rsplit('\n', 1)[0]
                        wrote = client.write(url_str, content_to_write)
                    if wrote is True:
                        # Verify write by re-reading (API is sync, no delay needed)
                        verify = client.read(url_str)
                        if verify and content_to_write[:30] in verify:
                            if result.get("status") != "hit+write":
                                result["status"] = "wrote"
                        else:
                            if result.get("status") != "hit+write":
                                result["status"] = "wrote_fake"
                    elif wrote is None:
                        continue
                    else:
                        if result.get("status") != "hit+write":
                            result["status"] = "error_write"
                else:
                    if result.get("status") != "hit+write":
                        result["status"] = "error"
            else:
                if result.get("status") != "hit+write":
                    result["status"] = "occupied" if existing else "empty"

            return result
            
        result["status"] = "error"
        return result

    # ── Display ───────────────────────────────────────────────────────────

    def _print_header(self):
        """Print startup banner."""
        current_str = index_to_string(self.current_idx)
        print()
        print("=" * 60)
        print(f"  🔍 URL BRUTE-FORCER v{VERSION}")
        print("=" * 60)
        print(f"  Target:    {self.target} ({self.site_url})")
        print(f"  Mode:      {self.mode.upper()}")
        print(f"  Workers:   {self.workers}")
        print(f"  Charset:   a-z, 0-9 ({len(CHARSET)} chars)")
        print(f"  Resume:    /{current_str} (index #{self.current_idx})")
        if self.write_msg:
            preview = self.write_msg[:50] + ("..." if len(self.write_msg) > 50 else "")
            print(f"  Message:   \"{preview}\"")
        if self.using_proxies:
            print(f"  Proxy:     ✓ Active")
        print(f"  Results:   {self.results.filepath}")
        print("=" * 60)
        print()

    def _print_status_line(self, url_str):
        """Print a compact status line that overwrites itself."""
        if self.quiet_ui:
            return
            
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        hours, mins = divmod(mins, 60)
        time_str = f"{hours:02d}:{mins:02d}:{secs:02d}"

        with self.stats_lock:
            checked = self.stats["checked"]
            hits = self.stats["hits"]
            errors = self.stats["errors"]
            wrote = self.stats["wrote"]
            skipped = self.stats["skipped_mine"]
            rots = self.stats["proxies_rotated"]
            revisions = self.stats["revisions"]

        rate = checked / elapsed if elapsed > 0 else 0

        proxy_str = f" | 🔄 Proxy: {rots} rots" if self.using_proxies else ""
        write_str = f" | ✍ {wrote}" if self.mode == "write" else ""
        rev_str = f" | 📝 V2+: {revisions}" if revisions > 0 else ""

        sys.stdout.write(
            f"\r  ⏱ {time_str} | 📍 /{url_str} | "
            f"✅ {hits} found | ❌ {errors} errors | "
            f"🔄 {checked} checks ({rate:.1f}/s){write_str}{rev_str}{proxy_str}    "
        )
        sys.stdout.flush()

    def _print_hit(self, url_str, content_len, content="", is_write_hit=False, is_revision=False):
        """Print to screen when something is found."""
        if is_revision:
            icon = "📝"; tag = "REVISION"
        elif is_write_hit:
            icon = "🎯"; tag = "SAVED"
        else:
            icon = "✨"; tag = "FOUND!"
        
        clean_url = f"{self.site_url.replace('https://', '')}/{url_str}"
        
        if self.quiet_ui:
            # Child process mode: minimal output to prevent pipe saturation
            sys.stdout.write(f"  {icon} {tag} {clean_url}\n")
            sys.stdout.flush()
            return
        
        # Interactive mode: show content preview
        sys.stdout.write(f"\r{' '*100}\r")
        out = f"  {icon} {tag} {clean_url}\n"
        if content:
            out += "     " + "─"*50 + "\n"
            lines = content.split('\n')
            for line in lines[:5]:
                out += f"     | {line.strip()}\n"
            if len(lines) > 5:
                out += f"     | ... [{len(lines)-5} more lines, see .txt file]\n"
        sys.stdout.write(out)
        sys.stdout.flush()

    def _print_wrote_batched(self, message):
        """Batch pushing to UI array to be flushed independently, drastically reducing I/O lock up."""
        if not hasattr(self, '_print_batch'):
            self._print_batch = []
            self._last_batch_time = time.time()
        self._print_batch.append(message)

    def _flush_print_batch(self):
        """Flush the saved prints array every 2 seconds to terminal to conserve CPU."""
        if self.quiet_ui:
            if hasattr(self, '_print_batch'):
                self._print_batch.clear()
            return
        if hasattr(self, '_print_batch') and self._print_batch:
            if time.time() - self._last_batch_time >= 2.0:
                sys.stdout.write(f"\r{' '*100}\r")
                for msg in self._print_batch:
                    sys.stdout.write(msg + "\n")
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._print_batch.clear()
                self._last_batch_time = time.time()

    def _print_rate_limit_warning(self):
        pass

    def _print_report(self):
        """Print final report."""
        elapsed = time.time() - self.start_time
        mins, secs = divmod(int(elapsed), 60)
        hours, mins = divmod(mins, 60)
        current_str = index_to_string(self.current_idx)

        print(f"\r{' '*100}\r")
        print()
        print("=" * 60)
        print("  📊 FINAL REPORT")
        print("=" * 60)
        print(f"  ⏱  Duration: {hours:02d}:{mins:02d}:{secs:02d}")
        print(f"  📍 Last position: /{current_str} (index #{self.current_idx})")
        print(f"  🔄 URLs checked: {self.stats['checked']}")
        print(f"  ✨ New content found: {self.stats['hits']}")
        print(f"  📝 Revisions (V2+): {self.stats['revisions']}")
        if self.filter_enabled:
            print(f"  🌍 Foreign languages skipped: {self.stats['foreign_skipped']}")
        print(f"  🔁 Duplicates skipped: {self.stats['duplicates']}")
        print(f"  🏠 Own messages skipped: {self.stats['skipped_mine']}")
        print(f"  📝 Empty/404: {self.stats['empty']}")
        print(f"  ❌ Network errors: {self.stats['errors']}")
        if self.mode == "write":
            print(f"  ✍  Messages written: {self.stats['wrote']}")
        print(f"  📁 Results file: {self.results.filepath}")
        print(f"  📊 Total results in file: {self.results.get_count()}")
        print("=" * 60)
        print()

    # ── Main Loop ─────────────────────────────────────────────────────────

    def run(self):
        """Main execution loop."""
        if self.target == "all":
            return self._run_all_supervisor()
        
        # Hard socket-level timeout: catches SOCKS proxy hangs that
        # requests' timeout parameter cannot reach (e.g. proxy accepts
        # TCP but never completes SOCKS handshake)
        import socket
        socket.setdefaulttimeout(self.site_timeout + 2)  # slightly above request timeout
        
        # Override global timeout so all client libraries use per-site value
        config.SITE_READ_TIMEOUT = self.site_timeout
            
        if self.using_proxies:
            print(f"  ⚠️  {self.target} configured for IP protection: Proxies forced")
            self._enable_proxies()

        self._print_header()

        rate_limit_cooldown = 0
        
        if getattr(self.args, 'quiet_ui', False):
            def _stats_emitter():
                while self.running:
                    with self.stats_lock:
                        emit = dict(self.stats)
                    emit["retry_pending"] = len(getattr(self, 'retry_queue', []))
                    sys.stderr.write(f"@@STATS@@{json.dumps(emit)}\n")
                    sys.stderr.flush()
                    time.sleep(1)
            import threading
            threading.Thread(target=_stats_emitter, daemon=True).start()

        executor = ThreadPoolExecutor(max_workers=self.workers)
        futures = {}
        try:
            while self.running:
                if rate_limit_cooldown > 0:
                    if not self.quiet_ui:
                        sys.stdout.write(f"\r  💤 Rate-limit pause: {rate_limit_cooldown}s...    ")
                        sys.stdout.flush()
                    time.sleep(1)
                    rate_limit_cooldown -= 1
                    continue
                
                self._flush_print_batch()

                # Maintain a full queue of workers using a sliding window
                while len(futures) < self.workers and self.running:
                    if getattr(self, 'retry_queue', deque()):
                        idx = self.retry_queue.popleft()
                    else:
                        idx = self.current_idx
                        self.current_idx += 1
                    future = executor.submit(self._process_url, idx)
                    futures[future] = idx
                
                if not futures:
                    continue

                # Wait for at least one future to complete
                done, not_done = wait(
                    futures.keys(), return_when=FIRST_COMPLETED, timeout=1.0
                )
                
                for future in done:
                    idx = futures.pop(future)
                    try:
                        r = future.result()
                    except Exception:
                        r = {"idx": idx, "status": "error", "url": "???"}
                        
                    with self.stats_lock:
                        self.stats["checked"] += 1
                        if r["status"] in ["hit", "hit+write"]:
                            self.stats["hits"] += 1
                            self._print_hit(r["url"], r.get("content_len", 0),
                                            content=r.get("content", ""),
                                            is_write_hit=(r["status"] == "hit+write"))
                        elif r["status"] == "revision":
                            self.stats["hits"] += 1
                            self.stats["revisions"] += 1
                            self._print_hit(r["url"], r.get("content_len", 0),
                                            content=r.get("content", ""),
                                            is_revision=True)
                        elif r["status"] == "wrote":
                            self.stats["wrote"] += 1
                            msg = f"  ✅ WROTE+VERIFIED! {self.site_url.replace('https://', '')}/{r['url']}"
                            self._print_wrote_batched(msg)
                        elif r["status"] == "wrote_fake":
                            self.stats["wrote_fake"] += 1
                            msg = f"  ⚠️  WROTE but NOT verified {self.site_url.replace('https://', '')}/{r['url']}"
                            self._print_wrote_batched(msg)
                        elif r["status"] == "empty":
                            self.stats["empty"] += 1
                        elif r["status"] in ["duplicate", "occupied"]:
                            self.stats["duplicates"] += 1
                        elif r["status"] == "foreign":
                            self.stats["foreign_skipped"] += 1
                        elif r["status"] == "mine":
                            self.stats["skipped_mine"] += 1
                        elif r["status"] in ["error", "rate_limit", "error_write"]:
                            if not hasattr(self, 'retry_queue'): self.retry_queue = deque()
                            self.retry_queue.append(r["idx"])
                            self.stats["errors"] += 1
                        else:
                            if not hasattr(self, 'retry_queue'): self.retry_queue = deque()
                            self.retry_queue.append(r["idx"])
                            self.stats["errors"] += 1

                last_url = index_to_string(self.current_idx - 1)
                
                # Show retry queue size in status if it exists
                q_size = len(getattr(self, 'retry_queue', deque()))
                status_suffix = f" (Retrying {q_size})" if q_size > 0 else ""
                self._print_status_line(last_url + status_suffix)

                # Auto-save every 200 checks
                if self.stats["checked"] % 200 == 0:
                    self._save_state()



        except KeyboardInterrupt:
            self.running = False
            if not self.quiet_ui:
                print("\n  🛑 Interrupted by user")
            
        # Final save and report
        self._save_state()
        self.results.flush_dedup()
        self.url_history.save()
        if not self.quiet_ui:
            self._print_report()
            print("  💾 State saved. Restart to continue where you left off.\n")
        
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            executor.shutdown(wait=False)
            
        import os
        os._exit(0)

    def _run_all_supervisor(self):
        """Run all sites concurrently using subprocesses and rich.Live UI."""
        print("\n  🚀 MULTI-SITE LAUNCH: cl1p, justpaste, rentry")
        print("  ===============================================================")
        print("  Scanning all targets. Hits from all sites will appear below in real-time.\n")
        
        from rich.live import Live
        from rich.table import Table
        import select
        import subprocess
        import os
        
        live_stats = {
            "cl1p": {"checked": 0, "hits": 0, "wrote": 0, "wrote_fake": 0, "errors": 0, "empty": 0, "duplicates": 0, "foreign_skipped": 0, "skipped_mine": 0, "retry_pending": 0},
            "justpaste": {"checked": 0, "hits": 0, "wrote": 0, "wrote_fake": 0, "errors": 0, "empty": 0, "duplicates": 0, "foreign_skipped": 0, "skipped_mine": 0, "retry_pending": 0},
            "rentry": {"checked": 0, "hits": 0, "wrote": 0, "wrote_fake": 0, "errors": 0, "empty": 0, "duplicates": 0, "foreign_skipped": 0, "skipped_mine": 0, "retry_pending": 0}
        }
        
        procs = {}
        for tgt in ["cl1p", "justpaste", "rentry"]:
            tgt_mode = self.mode
            # justpaste and rentry are read-only
            if tgt in ["justpaste", "rentry"]:
                tgt_mode = "read"

            cmd = [sys.executable, "-u", sys.argv[0], "--mod2", "-t", tgt, "--quiet-ui"]
            if getattr(self.args, 'reset', False): cmd.append("--reset")
            if getattr(self.args, 'start', ''): cmd.extend(["--start", self.args.start])
            if getattr(self.args, 'filter', False): cmd.append("--filter")

            if tgt_mode == "write" and tgt == "cl1p":
                if getattr(self.args, 'write_file', None): cmd.extend(["-wf", self.args.write_file])
                elif getattr(self.args, 'write', None): cmd.extend(["-w", self.args.write])
                
            procs[tgt] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1048576)

        show_filter_col = getattr(self.args, 'filter', False)
        start_time = time.time()
        
        # Rolling speed: track (timestamp, checked) snapshots per site
        SPEED_WINDOW = 30  # seconds
        speed_snapshots = {tgt: [(time.time(), 0)] for tgt in ["cl1p", "justpaste", "rentry"]}
        
        # Auto-restart tracking
        restart_counts = {tgt: 0 for tgt in ["cl1p", "justpaste", "rentry"]}
        MAX_RESTARTS = 3
        
        def _build_cmd(tgt):
            """Build the subprocess command for a target site."""
            tgt_mode = self.mode
            if tgt in ["justpaste", "rentry"]:
                tgt_mode = "read"
            cmd = [sys.executable, "-u", sys.argv[0], "--mod2", "-t", tgt, "--quiet-ui"]
            if getattr(self.args, 'reset', False): cmd.append("--reset")
            if getattr(self.args, 'start', ''): cmd.extend(["--start", self.args.start])
            if getattr(self.args, 'filter', False): cmd.append("--filter")
            if tgt_mode == "write" and tgt == "cl1p":
                if getattr(self.args, 'write_file', None): cmd.extend(["-wf", self.args.write_file])
                elif getattr(self.args, 'write', None): cmd.extend(["-w", self.args.write])
            return cmd
        
        def _restart_proc(tgt, live_obj):
            """Restart a dead subprocess and re-register its fds."""
            cmd = _build_cmd(tgt)
            new_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1048576)
            procs[tgt] = new_proc
            restart_counts[tgt] += 1
            # Reset stats for clean speed tracking
            speed_snapshots[tgt] = [(time.time(), live_stats[tgt].get("checked", 0))]
            # Register new fds
            for stream_name, stream_obj in [('stdout', new_proc.stdout), ('stderr', new_proc.stderr)]:
                new_fd = stream_obj.fileno()
                os.set_blocking(new_fd, False)
                poller.register(new_fd, select.EPOLLIN)
                fd_to_tgt[new_fd] = (tgt, new_proc, stream_name)
                active_fds.add(new_fd)
                fd_buffers[new_fd] = bytearray()
            try:
                live_obj.console.print(f"  🔄 {tgt} restarted (attempt {restart_counts[tgt]}/{MAX_RESTARTS})", style="bold cyan")
            except: pass

        def generate_table():
            now = time.time()
            
            table = Table(title="Live Scanner Performance", style="cyan")
            table.add_column("Site", justify="right", style="cyan", no_wrap=True)
            table.add_column("URLs Scanned", justify="center", style="magenta")
            table.add_column("Speed", justify="center", style="bold green")
            table.add_column("Hits Found", justify="center", style="green")
            table.add_column("Written OK", justify="center", style="yellow")
            table.add_column("Empty/404", justify="center", style="dim white")
            if show_filter_col:
                table.add_column("Filtered", justify="center", style="dim yellow")
            table.add_column("Errors", justify="center", style="red")
            table.add_column("Retrying", justify="center", style="bold yellow")
            for tgt in ["cl1p", "justpaste", "rentry"]:
                s = live_stats[tgt]
                is_alive = procs[tgt].poll() is None
                status = "🟡" if is_alive else "🪦"
                retry_pending = s.get("retry_pending", 0)
                display_name = "justpaste (READ)" if tgt == "justpaste" else tgt
                
                # Rolling speed: urls checked in the last SPEED_WINDOW seconds
                current_checked = s.get("checked", 0)
                snapshots = speed_snapshots[tgt]
                snapshots.append((now, current_checked))
                # Prune old snapshots
                cutoff = now - SPEED_WINDOW
                while len(snapshots) > 1 and snapshots[0][0] < cutoff:
                    snapshots.pop(0)
                # Calculate rate
                if len(snapshots) >= 2 and is_alive:
                    dt = max(0.01, snapshots[-1][0] - snapshots[0][0])
                    delta_checked = snapshots[-1][1] - snapshots[0][1]
                    speed = int((delta_checked / dt) * 60)  # per minute
                else:
                    speed = 0

                row = [
                    f"{display_name} {status}",
                    str(current_checked),
                    f"{speed} u/m",
                    str(s.get("hits", 0)),
                    str(s.get("wrote", 0) + s.get("wrote_fake", 0)),
                    str(s.get("empty", 0)),
                ]
                if show_filter_col:
                    filtered = s.get("duplicates", 0) + s.get("foreign_skipped", 0) + s.get("skipped_mine", 0)
                    row.append(str(filtered))
                row += [
                    str(s.get("errors", 0)),
                    str(retry_pending) if retry_pending > 0 else "-",
                ]
                table.add_row(*row)
            return table

        with Live(generate_table(), refresh_per_second=2, screen=False) as live:
            poller = select.epoll()
            fd_to_tgt = {}     # fd -> (target_name, proc, 'stdout'|'stderr')
            for tgt, p in procs.items():
                # Register stdout for display output
                out_fd = p.stdout.fileno()
                poller.register(out_fd, select.EPOLLIN)
                fd_to_tgt[out_fd] = (tgt, p, 'stdout')
                os.set_blocking(out_fd, False)
                # Register stderr for stats
                err_fd = p.stderr.fileno()
                poller.register(err_fd, select.EPOLLIN)
                fd_to_tgt[err_fd] = (tgt, p, 'stderr')
                os.set_blocking(err_fd, False)
                
            try:
                active_fds = set(fd_to_tgt.keys())
                last_progress = time.time()
                prev_totals = {tgt: 0 for tgt in procs}
                STALE_TIMEOUT = 120
                RATE_LIMIT_CODES = {403, 429, 503}
                fd_buffers = {fd: bytearray() for fd in fd_to_tgt}
                
                while active_fds:
                    events = poller.poll(0.5)
                    for fd, event in events:
                        if fd not in fd_to_tgt:
                            continue
                        tgt, p, pipe_type = fd_to_tgt[fd]
                        if event & select.EPOLLIN:
                            while True:
                                try:
                                    chunk = os.read(fd, 65536)
                                    if not chunk:
                                        break
                                    fd_buffers[fd].extend(chunk)
                                except (BlockingIOError, OSError):
                                    break
                                    
                            while b'\n' in fd_buffers[fd]:
                                line_end = fd_buffers[fd].index(b'\n')
                                line_b = fd_buffers[fd][:line_end]
                                del fd_buffers[fd][:line_end+1]
                                
                                text = line_b.decode('utf-8', errors='replace')
                                if text.startswith("@@STATS@@"):
                                    try:
                                        stats = json.loads(text[9:])
                                        live_stats[tgt]["checked"] = stats.get("checked", 0)
                                        live_stats[tgt]["hits"] = stats.get("hits", 0)
                                        live_stats[tgt]["wrote"] = stats.get("wrote", 0)
                                        live_stats[tgt]["wrote_fake"] = stats.get("wrote_fake", 0)
                                        live_stats[tgt]["errors"] = stats.get("errors", 0)
                                        live_stats[tgt]["empty"] = stats.get("empty", 0)
                                        live_stats[tgt]["duplicates"] = stats.get("duplicates", 0)
                                        live_stats[tgt]["foreign_skipped"] = stats.get("foreign_skipped", 0)
                                        live_stats[tgt]["skipped_mine"] = stats.get("skipped_mine", 0)
                                        live_stats[tgt]["retry_pending"] = stats.get("retry_pending", 0)
                                    except: pass
                                else:
                                    text_str = text.strip('\r')
                                    if text_str:
                                        try:
                                            live.console.print(text_str, markup=False, highlight=False)
                                        except Exception:
                                            sys.__stdout__.write(text_str.encode('ascii', 'ignore').decode('ascii') + '\n')
                                            sys.__stdout__.flush()
                                        
                        if event & (select.EPOLLHUP | select.EPOLLERR):
                            try: poller.unregister(fd)
                            except: pass
                            active_fds.discard(fd)
                    
                    # Track progress
                    current_totals = {tgt: live_stats[tgt].get("checked", 0) for tgt in procs}
                    if current_totals != prev_totals:
                        last_progress = time.time()
                        prev_totals = dict(current_totals)
                    
                    # Per-process death: clean up dead process fds and auto-restart
                    for tgt, p in list(procs.items()):
                        if p.poll() is not None:
                            dead_fds = [fd for fd, (t, proc, _) in fd_to_tgt.items() if t == tgt and fd in active_fds]
                            for fd in dead_fds:
                                try:
                                    while True:
                                        try:
                                            chunk = os.read(fd, 4096)
                                            if not chunk: break
                                            fd_buffers[fd].extend(chunk)
                                        except OSError: break
                                    while b'\n' in fd_buffers[fd]:
                                        line_end = fd_buffers[fd].index(b'\n')
                                        line_b = fd_buffers[fd][:line_end]
                                        del fd_buffers[fd][:line_end+1]
                                        text = line_b.decode('utf-8', errors='replace')
                                        if text.startswith("@@STATS@@"):
                                            try:
                                                stats = json.loads(text[9:])
                                                for k in stats:
                                                    if k in live_stats[tgt]:
                                                        live_stats[tgt][k] = stats[k]
                                            except: pass
                                    poller.unregister(fd)
                                except: pass
                                active_fds.discard(fd)
                                fd_buffers.pop(fd, None)
                            rc = p.returncode
                            if rc != 0 and dead_fds:
                                try:
                                    live.console.print(f"  ⚠️  {tgt} process exited with code {rc}", style="bold yellow")
                                except: pass
                            
                            # Auto-restart if under the limit
                            if restart_counts[tgt] < MAX_RESTARTS:
                                try:
                                    time.sleep(2)  # Brief cooldown before restart
                                    _restart_proc(tgt, live)
                                except Exception as e:
                                    try:
                                        live.console.print(f"  ❌ {tgt} restart failed: {e}", style="bold red")
                                    except: pass
                            else:
                                if dead_fds:  # Only print once
                                    try:
                                        live.console.print(f"  💀 {tgt} permanently dead (max {MAX_RESTARTS} restarts reached)", style="bold red")
                                    except: pass
                    
                    # Stale timeout
                    now = time.time()
                    if now - last_progress > STALE_TIMEOUT:
                        try:
                            live.console.print(f"\n  ⏰ No progress for {STALE_TIMEOUT}s, shutting down stale processes...", style="bold yellow")
                        except: pass
                        for p in procs.values():
                            try: p.kill()
                            except: pass
                        active_fds.clear()
                        break
                            
                    live.update(generate_table())
                    
            except KeyboardInterrupt:
                live.console.print("\n  🛑 Shutting down supervisor...", style="bold red")

            for p in procs.values():
                try: p.send_signal(signal.SIGINT)  # SIGINT triggers _handle_interrupt → _save_state
                except: pass
            
            # Give subprocesses time to flush retry queues to disk
            for p in procs.values():
                try: p.wait(timeout=3)
                except: 
                    try: p.kill()
                    except: pass

        print("  ✅ Scan finished.")
        print("  💾 State saved. Restart to continue where you left off.\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def load_file_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception as e:
        print(f"  ✗ Error reading file {filepath}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="proxy_scanner",
        description="🔍 HTTP Proxy Brute-Forcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --mod2 -t cl1p
  python3 main.py --mod2 -t rentry
  python3 main.py --mod2 -t cl1p -w "message"
  python3 main.py --mod2 -t all -tcf altrooo/messaggiocl1p.txt
  python3 main.py --mod2 -t cl1p --reset
  python3 main.py --mod2 -t cl1p --start a9i
  python3 main.py --mod2 -t all --reset-all
        """
    )

    parser.add_argument("-t", "--target", choices=["cl1p", "justpaste", "rentry", "all"], required=True,
                        help="Target site (cl1p, justpaste, rentry or 'all')")
    
    # Write arguments
    parser.add_argument('-w', '--write', help='Write message (only supported on cl1p.net)')
    parser.add_argument('-wf', '--write-file', help='Write message from file (only supported on cl1p.net)')
                        
    parser.add_argument("--reset", action="store_true",
                        help="Reset scan for a specific site from scratch")
    parser.add_argument("--reset-all", action="store_true",
                        help="Reset ALL sites and counters from scratch")
    parser.add_argument("--start", type=str, default="",
                        help="Start from a specific URL (e.g., --start abc)")
    parser.add_argument("-f", "--filter", action="store_true",
                        help="Enable foreign language filter: skip content where >50%% of characters are non-Latin script")
    parser.add_argument("--quiet-ui", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # If first time running and user needs cl1p token, prompt them (only in the supervisor, not child workers)
    if not args.quiet_ui and args.target in ["cl1p", "all"]:
        import src.config as config
        try:
            import src.secrets as secret_cfg
            token1 = getattr(secret_cfg, 'CL1P_API_TOKEN', "")
        except ImportError:
            token1 = getattr(config, 'CL1P_API_TOKEN', "")
            
        if not token1:
            print("\n  [ SETUP ] Accessing cl1p.net requires a free API token.")
            print("  If you don't have one, get it from your dashboard on cl1p.net.")
            new_token = input("  Enter your CL1P API token: ").strip()
            if new_token:
                secrets_path = Path("src/secrets.py")
                # Append or create
                with open(secrets_path, "a") as f:
                    f.write(f"\nCL1P_API_TOKEN = '{new_token}'\n")
                print("  [ SETUP ] ✓ Token saved securely to src/secrets.py (ignored by git).")
                print("  Restarting to apply...\n")
                import os
                # Relaunch the exact same command
                os.execv(sys.executable, ['python3'] + sys.argv)
            else:
                print("  [ SETUP ] Skipping. Cl1p functionality will be broken until configured.")

    # Load files
    if getattr(args, 'write_file', None): args.write = load_file_content(args.write_file)

    # Determine mode based on whether a write command is active for the target
    args.mode = "read"
    if getattr(args, 'write', None):
        if args.target in ["cl1p", "all"]:
            args.mode = "write"
            
            # justpaste and rentry do not support writing reliably.
            # So if `-t all` is used with a global `-w`, we don't throw an error,
            # the supervisor simply routes read strict to them.
        else:
            parser.error(f"{args.target} does not support writing.")

    # Handle reset-all
    if args.reset_all:
        targets = ["cl1p", "justpaste (READ-ONLY)", "rentry"]
        state = {}
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
            except:
                pass
        
        for tgt in targets:
            for mode in ["read", "write"]:
                state.pop(f"{tgt}_{mode}", None)
        
        STATE_FILE.parent.mkdir(exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
        print(f"\n  [ RESET ] ✨ ALL SITES RESET TO INDEX 0!")
        print(f"  [ RESET ] ⏪ The scanning positions have been reset.\n")
        sys.exit(0)

    # Handle reset
    if args.reset:
        state = {}
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
            except:
                pass
                
        state_key = f"{args.target}_{args.mode}"
        old_idx = state.get(state_key, 0)
        state.pop(state_key, None)
        
        STATE_FILE.parent.mkdir(exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
            
        old_str = index_to_string(old_idx)
        print(f"\n  [ RESET ] ✨ Site {args.target} FULLY RESET!")
        print(f"  [ RESET ] ⏪ Previous index was #{old_idx} (/{old_str})\n")
        sys.exit(0)

    # Handle custom start
    if args.start:
        idx = string_to_index(args.start)
        state = {}
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
            except:
                pass
        state_key = f"{args.target}_{args.mode}"
        state[state_key] = idx
        STATE_FILE.parent.mkdir(exist_ok=True)
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
        print(f"  ✓ Start set to /{args.start} (index #{idx})")

    scanner = PasteScanner(args)
    scanner.run()


if __name__ == "__main__":
    main()
