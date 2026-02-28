import time
import base64
from bs4 import BeautifulSoup
from .base import BaseSite
from .. import utils, config

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

class CopyPasteClient(BaseSite):
    def get_name(self):
        return "copy-paste.online"
        
    def _get_headers(self):
        return {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def read(self):
        timeout = getattr(self.session, 'timeout', config.SITE_READ_TIMEOUT)
        max_retries = 0 if timeout < config.SITE_READ_TIMEOUT else 2
        retry_delay = config.SITE_RETRY_DELAY
        
        for attempt in range(max_retries + 1):
            try:
                headers = self._get_headers()
                response = self.session.get('https://copy-paste.online/', headers=headers, timeout=timeout)
                
                # Check for rate limits or paywalls specific to this site
                # content "user agents" is present in normal page, so we removed that check.
                if "premium plan" in response.text.lower() and "subscribe" in response.text.lower():
                     # Only block if it really looks like a paywall blocker
                    utils.debug_log("CopyPaste rate limit detected", response.text[:200])
                    # Return None immediately if blocked
                    return None
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Try different selectors as they might change
                    textarea = soup.find('textarea', {'id': 'text'})
                    if not textarea:
                        textarea = soup.find('textarea', {'class': 'COPYPASTE'})
                    if not textarea:
                        textarea = soup.find('textarea')
                        
                    if textarea:
                        content = textarea.text.strip()
                        if content == "" and attempt < max_retries:
                            time.sleep(retry_delay)
                            continue
                        return content
                        
                    # If we are here, textarea was NOT found
                    utils.debug_log("CopyPaste textarea not found", response.text[:200])
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                    return None # Return None (Error) instead of empty string
                else:
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                    return None
                    
            except Exception as e:
                utils.debug_log("CopyPaste read exception", str(e))
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                return None
        return None

    def write(self, content):
        try:
            # 1. Initial Visit (cookies/headers)
            headers = self._get_headers()
            timeout = getattr(self.session, 'timeout', 30)
            self.session.get('https://copy-paste.online/', headers=headers, timeout=timeout)
            time.sleep(0.5)
            
            # 2. Prepare POST
            headers_post = headers.copy()
            headers_post['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers_post['X-Requested-With'] = 'XMLHttpRequest'
            headers_post['Origin'] = 'https://copy-paste.online'
            headers_post['Referer'] = 'https://copy-paste.online/'
            
            # Base64 encode data
            data_encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')
            post_data = {'fname': 'copypaste', 'data': data_encoded, 'mycode': ''}
            
            response = self.session.post('https://copy-paste.online/func/func.php', data=post_data, headers=headers_post, timeout=timeout)
            
            # Success is usually strictly returning a digit or 200 OK
            if response.status_code == 200 and response.text.strip().isdigit():
                return True
            return False
            
        except Exception as e:
            utils.debug_log("CopyPaste write exception", str(e))
            return False
