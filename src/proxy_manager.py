import re
import requests
import random
import time
from . import config, utils

class ProxyManager:
    def __init__(self):
        self.sources = config.PROXY_SOURCES
        self.proxies = [] # List of dicts: {'address': 'ip:port', 'protocol': 'http'|'socks4'|'socks5', 'fails': 0}
        
    def fetch_proxies(self, randomize=False):
        """Fetches free proxies from multiple sources."""
        print("🌍 Fetching free proxies from sources...", flush=True)
        raw_proxies = set()
        
        for source in self.sources:
            try:
                # Add a small timeout to not hang on dead sources
                response = requests.get(source, timeout=10)
                if response.status_code == 200:
                    text = response.text
                    # Extract IP:PORT lines
                    found = re.findall(r'[0-9]+(?:\.[0-9]+){3}:[0-9]+', text)
                    if found:
                        protocol = self._guess_protocol(source, text)
                        for p in found:
                            raw_proxies.add((p, protocol))
                        print(f"  ✓ {source.split('/')[-1]}: Found {len(found)} proxies ({protocol})", flush=True)
                    else:
                        print(f"  ✗ {source.split('/')[-1]}: No proxies found in payload", flush=True)
            except Exception as e:
                print(f"  ✗ {source.split('/')[-1]}: Failed to fetch ({e})")
                
        # Populate our list
        self.proxies = [{'address': p[0], 'protocol': p[1], 'fails': 0} for p in raw_proxies]
        print(f"=> Total unique proxies loaded: {len(self.proxies)}")
        
        # Shuffle if requested
        if randomize:
            random.shuffle(self.proxies)
        
    def _guess_protocol(self, source_url, payload_text):
        """Simple heuristic to guess protocol based on URL or content"""
        url_lower = source_url.lower()
        if 'socks5' in url_lower: return 'socks5'
        if 'socks4' in url_lower: return 'socks4'
        if 'http' in url_lower: return 'http'
        
        # If url doesn't say, default to http
        return 'http'
        
    def get_next_proxy(self):
        """Returns a proxy dict, preferring ones with fewer failures."""
        if not self.proxies:
            return None
            
        # Sort by fails, pick one of the best 50 randomly to ensure distribution
        sorted_proxies = sorted(self.proxies, key=lambda x: x['fails'])
        pool_size = min(50, len(sorted_proxies))
        return random.choice(sorted_proxies[:pool_size])
        
    def mark_failure(self, proxy_address):
        """Increments the failure count for a proxy. If it fails too much, we could remove it."""
        for p in self.proxies:
            if p['address'] == proxy_address:
                p['fails'] += 1
                break
                
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
