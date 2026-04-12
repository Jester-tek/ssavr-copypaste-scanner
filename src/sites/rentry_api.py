import re
import requests
import time
from html.parser import HTMLParser
import html as html_mod
from .. import config

class RentryExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text = []
        self.in_content = False
        self.div_level = 0
        self.article_level = 0

    def handle_starttag(self, tag, attrs):
        if not self.in_content:
            if tag == "div":
                for attr in attrs:
                    if attr[0] == "class" and attr[1] and "entry-text" in attr[1]:
                        self.in_content = True
                        self.div_level = 1
                        return
            elif tag == "article":
                self.in_content = True
                self.article_level = 1
        else:
            if tag == "div": self.div_level += 1
            elif tag == "article": self.article_level += 1
            elif tag == "a":
                for attr in attrs:
                    if attr[0] == "href":
                        url = attr[1]
                        if not url.startswith(("http", "mailto", "tel")):
                            url = "https://rentry.co" + url if url.startswith("/") else url
                        self.text.append(f"({url}) ")
            elif tag in ("br", "p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div"):
                self.text.append("\n")

    def handle_endtag(self, tag):
        if self.in_content:
            if tag == "div":
                self.div_level -= 1
                if self.div_level <= 0 and self.article_level <= 0:
                    self.in_content = False
            elif tag == "article":
                self.article_level -= 1
                if self.div_level <= 0 and self.article_level <= 0:
                    self.in_content = False
            elif tag in ("p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "div"):
                self.text.append("\n")

    def handle_data(self, data):
        if self.in_content:
            self.text.append(data)

class RentryClient:
    """Client per leggere contenuti da rentry.co via HTTP scraping."""
    
    RATE_LIMIT_CODES = {403, 429, 503}
    CLOUDFLARE_MARKERS = [
        "Just a moment...",
        "Checking your browser",
        "cf-browser-verification",
        "challenges.cloudflare.com",
        "_cf_chl_opt",
    ]
    
    def __init__(self, session_factory=None):
        self.base_url = "https://rentry.co"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        self.session_factory = session_factory
        self._session = None
        self.consecutive_errors = 0
        self.max_consecutive_errors = 5
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
        for marker in self.CLOUDFLARE_MARKERS:
            if marker in html:
                return True
        return False
    
    def _extract_content(self, html):
        """Extract the actual article content extracting the full DOM tree flawlessly."""
        extractor = RentryExtractor()
        extractor.feed(html)
        if not extractor.text:
            return None
            
        raw = "".join(extractor.text)
        
        # Strip all remaining HTML tags just in case
        text = re.sub(r'<[^>]+>', '', raw)
        text = html_mod.unescape(text)
        
        lines = [line.rstrip() for line in text.split('\n')]
        text = '\n'.join(lines).strip()
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Strip rentry's "Warning LINK" interstitial dialog boilerplate
        text = re.sub(r'\n*Warning\n+LINK\n+You are about to visit a link.*?Continue\s+\(\#\)\s+Cancel\s*', '', text, flags=re.DOTALL).strip()
        
        # Filtra messaggi interni di Rentry (Access Code)
        if hasattr(text, 'lower') and "access code required" in text.lower():
            return ""
            
        return text if text else None
        
    def read(self, url_path):
        """Read content from rentry."""
        # Su Rentry andiamo diretti all'url path per leggere il DOM, 
        # perché /raw/ richiede un codice di accesso speciale. Leggiamo l'HTML renderizzato.
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
                return None
                
            if resp.status_code != 200:
                self.consecutive_errors += 1
                return None
                
            html = resp.text
            
            if self._is_cloudflare(html):
                self.consecutive_errors += 1
                return None
                
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
        return self.consecutive_errors >= self.max_consecutive_errors

    def write(self, url_path, content):
        """Write content to rentry if it's empty using /api/new.
           Requires CSRF token from Django.
           Returns True if successful, False if occupied/error, None for network errors."""
        try:
            # Step 1: GET the homepage to acquire the CSRF cookie
            r = self.session.get(
                self.base_url,
                headers=self.headers,
                timeout=config.SITE_READ_TIMEOUT
            )
            csrf = self.session.cookies.get('csrftoken', '')
            if not csrf:
                # Try alternative cookie name
                csrf = self.session.cookies.get('csrf', '')
            if not csrf:
                self.consecutive_errors += 1
                return None

            # Step 2: POST to /api/new with CSRF token
            post_headers = dict(self.headers)
            post_headers['Referer'] = self.base_url + '/'
            
            data = {
                "csrfmiddlewaretoken": csrf,
                "text": content,
                "url": url_path,
                "edit_code": "proxyforcer123"
            }
            
            resp = self.session.post(
                f"{self.base_url}/api/new",
                headers=post_headers,
                data=data,
                timeout=config.SITE_WRITE_TIMEOUT
            )
            
            if resp.status_code in self.RATE_LIMIT_CODES:
                self.consecutive_errors += 1
                return None
                
            if resp.status_code != 200:
                self.consecutive_errors += 1
                return None
                
            try:
                js = resp.json()
            except:
                return False
                
            if js.get("status") == "200":
                self.consecutive_errors = 0
                return True
                
            # If status isn't 200, it probably means 'Url already exists' or other error
            return False
            
        except (requests.exceptions.Timeout, requests.RequestException):
            self.consecutive_errors += 1
            return None

