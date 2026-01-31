import time
import random
import re
from bs4 import BeautifulSoup
from .base import BaseSite
from .. import utils

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

class SsavrClient(BaseSite):
    def get_name(self):
        return "ssavr.com"

    def _get_headers(self):
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _extract_csrf_token(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta:
            return meta.get('content')
        input_token = soup.find('input', {'name': '_token'})
        if input_token:
            return input_token.get('value')
        match = re.search(r'["\']_token["\']\s*:\s*["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        return None

    def read(self):
        max_retries = 2
        retry_delay = 2
        
        for attempt in range(max_retries + 1):
            try:
                headers = self._get_headers()
                response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)
                
                if response.status_code != 200:
                    utils.debug_log(f"Ssavr non-200: {response.status_code}", f"Body: {response.text[:200]}")
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                    return None

                soup = BeautifulSoup(response.text, 'html.parser')
                textarea = soup.find('textarea', {'id': 'savr'})
                
                if textarea:
                    content = textarea.text.strip()
                    if content == "" and attempt < max_retries:
                        # Empty content might be a glitch, retry just in case
                        time.sleep(retry_delay)
                        continue
                    return content
                
                # If we are here, textarea was NOT found
                # This suggests the site structure changed or is blocked (e.g. Cloudflare)
                utils.debug_log("Ssavr textarea not found", response.text[:200])
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                return None # Return None (Error) instead of empty string if structure is missing
                
            except Exception as e:
                utils.debug_log("Ssavr read exception", str(e))
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                return None
        return None

    def write(self, content):
        try:
            headers = self._get_headers()
            # 1. GET to get CSRF
            response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)
            if response.status_code != 200:
                return False
                
            csrf_token = self._extract_csrf_token(response.text)
            if not csrf_token:
                return False
            
            # 2. POST to save
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['X-Requested-With'] = 'XMLHttpRequest'
            headers['Origin'] = 'https://www.ssavr.com'
            headers['Referer'] = 'https://www.ssavr.com/'
            
            post_data = {'_token': csrf_token, 'savr': content}
            response = self.session.post('https://www.ssavr.com/save', data=post_data, headers=headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return data.get('saved', False)
                except:
                    return False
            return False
            
        except Exception as e:
            utils.debug_log("Ssavr write exception", str(e))
            return False
