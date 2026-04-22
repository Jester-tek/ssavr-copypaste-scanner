import requests
import time
from .. import config

class Cl1pAPIClient:
    """Client per cl1p.net usando le API ufficiali con token."""
    
    RATE_LIMIT_CODES = {429, 503}
    
    def __init__(self, api_token, session_factory=None):
        self.api_token = api_token
        self.base_url = "https://api.cl1p.net"
        self.session_factory = session_factory
        self._session = None
        self.consecutive_errors = 0
        self.max_consecutive_errors = 10
        self.current_proxy = None
        
    @property
    def session(self):
        if self._session is None:
            if self.session_factory:
                self._session = self.session_factory()
            else:
                self._session = requests.Session()
        return self._session
    
    @property
    def _headers(self):
        return {
            'Content-Type': 'text/html; charset=UTF-8',
            'cl1papitoken': self.api_token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0.0.0 Safari/537.36',
        }
    
    def reset_session(self):
        """Reset session for proxy rotation."""
        if self._session:
            try:
                self._session.close()
            except:
                pass
        self._session = None
        self.consecutive_errors = 0

    def read(self, url_path):
        """
        Read a clip from cl1p.net via API.
        
        Returns:
            str: Content if found (non-empty)
            "": Empty clip / no content
            None: Network error or rate limit
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/{url_path}",
                headers=self._headers,
                timeout=config.SITE_READ_TIMEOUT
            )
            
            if resp.status_code == 200:
                text = resp.text.strip()
                # cl1p returns empty body or default message for empty clips
                if not text or "Content is destroyed" in text:
                    self.consecutive_errors = 0
                    return ""
                self.consecutive_errors = 0
                return text
                
            elif resp.status_code == 404:
                self.consecutive_errors = 0
                return ""
                
            elif resp.status_code in self.RATE_LIMIT_CODES:
                self.consecutive_errors += 1
                time.sleep(1)  # Backoff on rate limit
                return None
                
            else:
                self.consecutive_errors += 1
                return None
                
        except requests.exceptions.Timeout:
            self.consecutive_errors += 1
            return None
        except requests.RequestException:
            self.consecutive_errors += 1
            return None

    def write(self, url_path, content):
        """
        Write content to a cl1p URL.
        
        Returns:
            True: Written successfully
            False: Failed (URL occupied, rate limited, etc.)
            None: Network error
        """
        try:
            resp = self.session.post(
                f"{self.base_url}/{url_path}",
                data=content,
                headers=self._headers,
                timeout=config.SITE_WRITE_TIMEOUT
            )
            if resp.status_code in [200, 201]:
                self.consecutive_errors = 0
                return True
            elif resp.status_code in [400, 409]:
                # cl1p rejected the content (spam filter, blocked URL/crypto address)
                self.consecutive_errors = 0
                return False
            elif resp.status_code in self.RATE_LIMIT_CODES:
                self.consecutive_errors += 1
                time.sleep(1)
                return None
            return False
        except requests.RequestException:
            self.consecutive_errors += 1
            return None

    @property
    def is_rate_limited(self):
        """Check if we're likely being rate limited."""
        return self.consecutive_errors >= self.max_consecutive_errors
