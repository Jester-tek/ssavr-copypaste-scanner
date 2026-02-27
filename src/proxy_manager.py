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
                
        # Populate our list
        self.proxies = [{'address': p[0], 'protocol': p[1], 'fails': 0} for p in raw_proxies]
        print(f"=> Total unique proxies loaded: {len(self.proxies)}")
        
        # Shuffle if requested
        if randomize:
            random.shuffle(self.proxies)
        
    def _guess_protocol_from_url(self, source_url):
        """Guess protocol based on URL string"""
        url_lower = source_url.lower()
        if 'socks5' in url_lower: return 'socks5'
        if 'socks4' in url_lower: return 'socks4'
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
