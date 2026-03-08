import time
import random
import base64
from .base import BaseSite
from .. import utils

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Constant API key observed from the site's JavaScript
API_KEY = "webklsjfoi6jge3pgwe0few03"

class AirForShareClient(BaseSite):
    def get_name(self):
        return "airforshare.com"

    def _get_headers(self):
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Origin': 'https://www.airforshare.com',
            'Referer': 'https://www.airforshare.com/',
        }

    def read(self):
        timeout = getattr(self.session, 'timeout', 30)
        max_retries = 0 if timeout < 30 else 2  # No retries for proxy sessions
        retry_delay = 2

        for attempt in range(max_retries + 1):
            try:
                headers = self._get_headers()
                response = self.session.get(
                    'https://airforshare.com/apiv3/clip.php',
                    headers=headers,
                    timeout=timeout
                )

                if response.status_code != 200:
                    utils.debug_log(f"AirForShare non-200: {response.status_code}", f"Body: {response.text[:200]}")
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                    return None

                try:
                    data = response.json()
                except Exception:
                    utils.debug_log("AirForShare invalid JSON", response.text[:200])
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        continue
                    return None

                clip_text = data.get('clipText', '')
                if clip_text is None or clip_text == '':
                    return ''
                
                # clipText is base64 encoded
                try:
                    decoded = base64.b64decode(clip_text).decode('utf-8')
                    return decoded.strip()
                except Exception:
                    # If decoding fails, return the raw text
                    return clip_text.strip()

            except Exception as e:
                utils.debug_log("AirForShare read exception", str(e))
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    continue
                return None
        return None

    def write(self, content):
        try:
            headers = self._get_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

            post_data = {
                'api_key': API_KEY,
                'yourText': content
            }

            timeout = getattr(self.session, 'timeout', 30)
            response = self.session.post(
                'https://www.airforshare.com/apiv3/save.php',
                data=post_data,
                headers=headers,
                timeout=timeout
            )

            if response.status_code == 200:
                return True
            return False

        except Exception as e:
            utils.debug_log("AirForShare write exception", str(e))
            return False

    def clear(self):
        """Clear the clipboard for the current IP."""
        try:
            headers = self._get_headers()
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

            post_data = {
                'api_key': API_KEY,
                'yourText': ''
            }

            timeout = getattr(self.session, 'timeout', 30)
            response = self.session.post(
                'https://www.airforshare.com/apiv3/save.php',
                data=post_data,
                headers=headers,
                timeout=timeout
            )

            return response.status_code == 200

        except Exception as e:
            utils.debug_log("AirForShare clear exception", str(e))
            return False
