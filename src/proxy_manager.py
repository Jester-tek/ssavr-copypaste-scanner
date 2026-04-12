import re
import requests
import random
import time
import threading
from . import config, utils

class ProxyManager:
    def __init__(self):
        self.sources = config.PROXY_SOURCES
        self.proxies_list = [] # List of dicts
        self.proxies_dict = {} # Keyed by address
        self.lock = threading.Lock()
        self._refresh_running = False
        self._refresh_thread = None
        
    def fetch_proxies(self, randomize=False):
        """Fetches free proxies from multiple sources."""
        print("🌍 Fetching free proxies from sources...", flush=True)
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
                
            # Pick a random sample and return the one with least fails
            sample_size = min(20, len(self.proxies_list))
            candidates = random.sample(self.proxies_list, sample_size)
            return min(candidates, key=lambda x: x['fails'])
            
    def mark_failure(self, proxy_address):
        """Increments the failure count for a proxy in O(1) time."""
        with self.lock:
            if proxy_address in self.proxies_dict:
                self.proxies_dict[proxy_address]['fails'] += 1
                
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
