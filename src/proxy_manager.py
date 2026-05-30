import re
import requests
import random
import time
import json
import threading
from pathlib import Path
from datetime import datetime
from . import config, utils

CACHE_FILE = Path("data/proxies_cache.json")

class ProxyManager:
    def __init__(self):
        self.sources = config.PROXY_SOURCES
        self.proxies_list = [] # List of dicts
        self.proxies_dict = {} # Keyed by address
        self.working_proxies = [] # List of proxy addresses that recently worked
        self.lock = threading.Lock()
        self._refresh_running = False
        self._refresh_thread = None
        
    def fetch_proxies(self, randomize=False, force_fetch=False):
        """Fetches free proxies from cache or multiple sources."""
        with self.lock:
            # Check cache if not forcing fresh fetch
            if not force_fetch and CACHE_FILE.exists():
                try:
                    with open(CACHE_FILE, "r") as f:
                        cache_data = json.load(f)
                    
                    # If cache is < 30 minutes old, load it instead of fetching
                    age_seconds = time.time() - cache_data.get('timestamp', 0)
                    if age_seconds < (30 * 60):
                        print(f"🌍 Loading proxies from fresh cache ({int(age_seconds/60)} mins old)...", flush=True)
                        self.proxies_list = cache_data.get('proxies', [])
                        self.proxies_dict = {p['address']: p for p in self.proxies_list}
                        if randomize:
                            random.shuffle(self.proxies_list)
                        print(f"  ✓ {len(self.proxies_list)} proxies loaded instantly from cache", flush=True)
                        return
                except Exception:
                    pass
        
        print("🌍 Fetching fresh free proxies from network sources...", flush=True)
        raw_proxies = set()
        
        # Shuffle sources to distribute load and vary initial batch
        sources_list = list(self.sources)
        random.shuffle(sources_list)
        
        for source in sources_list:
            try:
                # Add a small timeout to not hang on dead sources
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    text = response.text
                    # Extract protocol://IP:PORT or just IP:PORT
                    # Protocol is optional: (?:(https?|socks[45])://)?
                    found = re.findall(r'(?:(?:(https?|socks[45])://))?([0-9]+(?:\.[0-9]+){3}:[0-9]+)', text, re.IGNORECASE)
                    
                    if found:
                        source_protocol = self._guess_protocol_from_url(source)
                        count = 0
                        for proto_group, addr in found:
                            # Use protocol from line if present, else fallback to source-based guess
                            protocol = proto_group.lower() if proto_group else source_protocol
                            raw_proxies.add((addr, protocol))
                            count += 1
                        print(f"  ✓ {source.split('/')[-1][:20]}: Found {count} proxies", flush=True)
                    else:
                        print(f"  ✗ {source.split('/')[-1][:20]}: No proxies found", flush=True)
            except Exception as e:
                print(f"  ✗ {source.split('/')[-1][:20]}: Failed ({type(e).__name__})")
                
        with self.lock:
            # Merge logic for infinite loop background fetch
            added = 0
            for addr, proto in raw_proxies:
                if addr not in self.proxies_dict:
                    new_p = {'address': addr, 'protocol': proto, 'fails': 0}
                    self.proxies_list.append(new_p)
                    self.proxies_dict[addr] = new_p
                    added += 1
                else:
                    # Give existing ones a second chance by decreasing fail count slightly
                    self.proxies_dict[addr]['fails'] = max(0, self.proxies_dict[addr]['fails'] - 1)
            
            # Auto-purge proxies with >25 fails to keep memory clean during days of run
            alive_proxies = [p for p in self.proxies_list if p['fails'] < 25]
            if len(alive_proxies) < len(self.proxies_list):
                self.proxies_list = alive_proxies
                self.proxies_dict = {p['address']: p for p in self.proxies_list}
            
            print(f"=> Total active proxies in pool: {len(self.proxies_list)} (+{added} fresh)")
            
            # Save the new fetch to cache
            try:
                CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(CACHE_FILE, "w") as f:
                    json.dump({
                        'timestamp': time.time(),
                        'proxies': self.proxies_list
                    }, f)
            except Exception as e:
                print(f"  [!] Could not save proxy cache: {e}")
            
            if randomize:
                random.shuffle(self.proxies_list)

    def start_auto_refresh(self, interval_mins=45):
        """Spawns a background thread to fetch new proxies indefinitely."""
        if self._refresh_running:
            return
        self._refresh_running = True
        self._refresh_thread = threading.Thread(target=self._auto_refresh_loop, args=(interval_mins,), daemon=True)
        self._refresh_thread.start()
        
    def _auto_refresh_loop(self, interval_mins):
        while self._refresh_running:
            for _ in range(interval_mins * 60):
                if not self._refresh_running: return
                time.sleep(1)
            print("\n🔄 [AUTO-TASK] Fetching fresh proxies in background...")
            self.fetch_proxies(randomize=True)
        
    def _guess_protocol_from_url(self, source_url):
        """Guess protocol based on URL string"""
        url_lower = source_url.lower()
        if 'socks5' in url_lower: return 'socks5'
        if 'socks4' in url_lower: return 'socks4'
        return 'http'
        
    def get_next_proxy(self):
        """Returns a proxy dict, picking the best out of a random sample (O(1) instead of O(N log N))."""
        with self.lock:
            if not self.proxies_list:
                return None
                
            # 90% chance to reuse a working proxy if available to avoid failing on known dead proxies
            if self.working_proxies and random.random() < 0.90:
                addr = random.choice(self.working_proxies)
                if addr in self.proxies_dict:
                    return self.proxies_dict[addr]
                
            # Pick a random sample and return the one with least fails
            sample_size = min(20, len(self.proxies_list))
            candidates = random.sample(self.proxies_list, sample_size)
            return min(candidates, key=lambda x: x['fails'])
            
    def mark_failure(self, proxy_address):
        """Increments the failure count for a proxy in O(1) time and removes it from the working pool."""
        with self.lock:
            if proxy_address in self.proxies_dict:
                self.proxies_dict[proxy_address]['fails'] += 1
                if proxy_address in self.working_proxies:
                    try:
                        self.working_proxies.remove(proxy_address)
                    except ValueError:
                        pass
                        
    def mark_success(self, proxy_address):
        """Resets the failure count for a proxy and adds it to the working pool."""
        with self.lock:
            if proxy_address in self.proxies_dict:
                self.proxies_dict[proxy_address]['fails'] = 0
                if proxy_address not in self.working_proxies:
                    self.working_proxies.append(proxy_address)
                
    def get_requests_dict(self, proxy):
        """Converts our proxy dict into a format requests.get(proxies=...) understands"""
        p_type = proxy['protocol']
        addr = proxy['address']
        
        # Using socks5h/socks4a to resolve DNS through proxy
        if p_type == 'socks5':
            url = f"socks5h://{addr}"
        elif p_type == 'socks4':
            url = f"socks4a://{addr}"
        else:
            url = f"http://{addr}"
            
        return {
            'http': url,
            'https': url
        }
