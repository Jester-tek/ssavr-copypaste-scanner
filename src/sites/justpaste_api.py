import re
import requests
import time
from html.parser import HTMLParser
from .. import config

class JustPasteExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.in_content = False
        self.div_level = 0

    def handle_starttag(self, tag, attrs):
        if not self.in_content:
            if tag == "div":
                for attr in attrs:
                    if attr[0] == "id" and attr[1] == "articleContent":
                        self.in_content = True
                        self.div_level = 1
                        return
                    elif attr[0] == "class" and attr[1] and "jp-article" in attr[1]:
                        self.in_content = True
                        self.div_level = 1
                        return
        else:
            if tag == "div":
                self.div_level += 1
            elif tag == "a":
                for attr in attrs:
                    if attr[0] == "href":
                        url = attr[1]
                        if url and not url.startswith(("#", "javascript")):
                            self.text.append(f"({url}) ")
            elif tag in ("br", "p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div"):
                self.text.append("\n")

    def handle_endtag(self, tag):
        if self.in_content:
            if tag == "div":
                self.div_level -= 1
                if self.div_level <= 0:
                    self.in_content = False
            elif tag in ("p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div"):
                self.text.append("\n")

    def handle_data(self, data):
        if self.in_content:
            self.text.append(data)

class JustPasteClient:
    """Client per leggere contenuti da justpaste.it via HTTP scraping."""
    
    RATE_LIMIT_CODES = {403, 429, 503}
    CLOUDFLARE_MARKERS = [
        "Just a moment...",
        "Checking your browser",
        "cf-browser-verification",
        "challenges.cloudflare.com",
        "_cf_chl_opt",
    ]
    
    def __init__(self, session_factory=None):
        self.base_url = "https://justpaste.it"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
        }
        self.session_factory = session_factory
        self._session = None
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5  # After this many, signal rate limit
        self.current_proxy = None
    
    @property
    def session(self):
        if self._session is None:
            if self.session_factory:
                self._session = self.session_factory()
            else:
                self._session = requests.Session()
        return self._session
    
    def reset_session(self):
        """Reset the session (useful after proxy rotation)."""
        if self._session:
            try:
                self._session.close()
            except:
                pass
        self._session = None
        self.consecutive_errors = 0
    
    def _is_cloudflare(self, html):
        """Detect if the response is a Cloudflare challenge page."""
        for marker in self.CLOUDFLARE_MARKERS:
            if marker in html:
                return True
        return False
    
    def _extract_content(self, html):
        """Extract the actual article content extracting the full DOM tree flawlessly."""
        extractor = JustPasteExtractor()
        extractor.feed(html)
        if not extractor.text:
            # Fallback wider regex search if structure dramatically deviates
            match = re.search(r'<article[^>]*>(.*?)</article>', html, re.DOTALL | re.IGNORECASE)
            if not match:
                return None
            extractor.text = [match.group(1)]
            
        raw = "".join(extractor.text)
        
        # In the fallback case, there might be tags left. Strip them.
        text = re.sub(r'<[^>]+>', '', raw)
        
        # Decode HTML entities
        import html as html_mod
        text = html_mod.unescape(text)
        
        # Clean up whitespace
        lines = [line.rstrip() for line in text.split('\n')]
        text = '\n'.join(lines).strip()
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        return text if text else None
    
    def _extract_title(self, html):
        """Extract the page title if available."""
        match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            title = match.group(1).strip()
            # Remove " - JustPaste.it" suffix
            title = re.sub(r'\s*[-–]\s*JustPaste\.it\s*$', '', title)
            return title if title else None
        return None

    def read(self, url_path):
        """
        Read content from a justpaste.it URL.
        
        Returns:
            str: Content text if found
            "": Empty / 404 / not found
            None: Network error or rate limit (signals need for retry/proxy change)
        """
        try:
            resp = self.session.get(
                f"{self.base_url}/{url_path}",
                headers=self.headers,
                timeout=config.SITE_READ_TIMEOUT,
                allow_redirects=True
            )
            
            if resp.status_code == 404:
                self.consecutive_errors = 0
                return ""
            
            if resp.status_code in self.RATE_LIMIT_CODES:
                self.consecutive_errors += 1
                return None  # Rate limited
            
            if resp.status_code != 200:
                self.consecutive_errors += 1
                return None
            
            html = resp.text
            
            # Cloudflare check
            if self._is_cloudflare(html):
                self.consecutive_errors += 1
                return None  # Blocked
            
            self.consecutive_errors = 0
            
            content = self._extract_content(html)
            if content:
                return content
            
            return ""
            
        except requests.exceptions.Timeout:
            self.consecutive_errors += 1
            return None
        except requests.RequestException:
            self.consecutive_errors += 1
            return None
    
    @property
    def is_rate_limited(self):
        """Check if we're likely being rate limited."""
        return self.consecutive_errors >= self.max_consecutive_errors
