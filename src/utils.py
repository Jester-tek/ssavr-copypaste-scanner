import re
import sys
import ipaddress
import logging
from datetime import datetime
from . import config

# Setup logging
logging.basicConfig(
    filename=config.DEBUG_LOG,
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def debug_log(message, data=None):
    logging.info(f"{message} - Data: {data}" if data else message)

def clean_text(text):
    if not text:
        return ""
    invisible_chars = ['\u00ad', '\u200b', '\u200c', '\u200d', '\ufeff', '\r']
    for char in invisible_chars:
        text = text.replace(char, '')
    # Convert newlines to space, then collapse multiple spaces
    text = re.sub(r'[\r\n]+', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def normalize_text_output(text):
    """
    Appends a soft hyphen (\u00ad) to text if the marker feature is enabled.
    This allows the tool to identify messages written by itself unless the user
    has the special .disable_advanced_features file (meaning they are the owner).
    """
    if not config.MARKER_ENABLED or not text:
        return text
    # Original logic: if text and not text.endswith('\n'): text = text + '\u00ad'
    # Wait, original logic was:
    # if text and not text.endswith('\n'):
    #     text = text + '\u00ad'
    # Effectively marking the text.
    if text and not text.endswith('\n') and '\u00ad' not in text:
         text = text + '\u00ad'
    return text

def is_mine(content, history_messages):
    """
    Determines if content was written by this tool.
    Checks against history AND looking for the hidden marker.
    """
    if not content:
        return False
    clean_content = clean_text(content)
    if clean_content in history_messages:
        return True
    
    # Check for marker
    # Original logic: `if self._txt_proc_enabled and content.endswith('\u00ad'):`
    # Here `MARKER_ENABLED` matches `_txt_proc_enabled`
    if config.MARKER_ENABLED and content.endswith('\u00ad'):
        return True
        
    return False

def extract_ip_from_text(text):
    if not text:
        return None
    candidates = re.findall(r'([0-9a-fA-F:.]{3,45})', text)
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None
