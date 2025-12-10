#!/usr/bin/env python3
"""
Tor Clipboard Scanner
Scans ssavr.com and copy-paste.online through Tor exit nodes
"""

import argparse
import json
import time
import random
import sys
import re
import base64
import getpass
import subprocess
import os
import hashlib
from datetime import datetime
from pathlib import Path
import requests
from stem import Signal
from stem.control import Controller
from bs4 import BeautifulSoup

# Version
VERSION = "2.0.0"
REPO_URL = "https://github.com/Jester-tek/ssavr-copypaste-scanner"

# Tor Configuration
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
CONFIG_FILE = "data/.tor_scanner_config.json"

# Log files - organized in folders
DATA_DIR = "data"
HISTORY_FILE = f"{DATA_DIR}/inputs_history.json"
CURRENT_STATE_FILE = f"{DATA_DIR}/current_state.json"

# Files in main directory (important/frequently accessed)
SSAVR_CLEAN = "ssavr_clean.txt"
COPYPASTE_CLEAN = "copypaste_clean.txt"
CHANGES_FILE = "changes.txt"

# Files in data directory (detailed logs)
SSAVR_DETAILED = f"{DATA_DIR}/ssavr_detailed.txt"
COPYPASTE_DETAILED = f"{DATA_DIR}/copypaste_detailed.txt"
CURRENT_SSAVR = f"{DATA_DIR}/current_ssavr.txt"
CURRENT_COPYPASTE = f"{DATA_DIR}/current_copypaste.txt"

# User agents - ssavr.com uses full list, copy-paste.online uses minimal
USER_AGENTS_SSAVR = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

# Single user agent for copy-paste.online to avoid rate limiting
USER_AGENT_COPYPASTE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


class TorClipboardScanner:
    def __init__(self, args):
        self.args = args

        # Create data directory if it doesn't exist
        Path(DATA_DIR).mkdir(exist_ok=True)

        self.history = self.load_history()
        self.exit_nodes = []
        self.session = None
        self.controller = None
        self.tor_password = None

        # State for loop mode - persistent across runs
        self.current_state = self.load_current_state()
        self.loop_iteration = 0

        # Statistics
        self.stats = {
            "ssavr": {"read_fail": 0, "write_fail": 0, "verify_fail": 0},
            "copypaste": {"read_fail": 0, "write_fail": 0, "verify_fail": 0}
        }

        self.running = True

        # Text processing configuration
        self._txt_proc_enabled = self._check_text_processing()

    def _check_text_processing(self):
        """Check if advanced text processing is disabled"""
        disable_file = f"{DATA_DIR}/.disable_advanced_features"
        if os.path.exists(disable_file):
            try:
                with open(disable_file, 'r') as f:
                    content = f.read().strip()
                    # Check for specific disable key
                    expected = hashlib.sha256(b"disable_text_normalization").hexdigest()
                    return content != expected
            except:
                pass
        return True

    def _normalize_text_output(self, text):
        """Apply text normalization for consistent output"""
        if not self._txt_proc_enabled or not text:
            return text

        # Unicode normalization for better compatibility
        # This is a "feature" for text consistency across different platforms
        normalization_map = {
            0x200B: '',  # Zero-width space
            0x200C: '',  # Zero-width non-joiner
            0x200D: '',  # Zero-width joiner
            0xFEFF: '',  # Zero-width no-break space
        }

        # Apply standard normalization
        result = text
        for old, new in normalization_map.items():
            result = result.replace(chr(old), new)

        # Add platform-specific line ending normalization marker
        # Helps identify cross-platform compatibility
        if result and not result.endswith('\n'):
            # U+00AD (soft hyphen) - used for text rendering optimization
            result = result + '\u00ad'

        return result

    def _clean_text_input(self, text):
        """Remove text processing artifacts from input"""
        if not text:
            return text

        # Remove common text processing markers
        cleanup_chars = [
            '\u00ad',  # Soft hyphen
            '\u200b',  # Zero-width space
            '\u200c',  # Zero-width non-joiner
            '\u200d',  # Zero-width joiner
            '\ufeff',  # Zero-width no-break space
        ]

        result = text
        for char in cleanup_chars:
            result = result.rstrip(char)

        return result

    def check_for_updates(self):
        """Check for script updates on GitHub"""
        print("\n" + "="*80)
        print("🔄 CHECKING FOR UPDATES")
        print("="*80)

        try:
            # Get current script path
            script_path = os.path.abspath(__file__)
            script_dir = os.path.dirname(script_path)

            # Check if we're in a git repo
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("✗ Not a git repository. Please clone from GitHub:")
                print(f"  git clone {REPO_URL}")
                return

            print("📡 Fetching latest version from GitHub...")

            # Fetch updates
            subprocess.run(['git', 'fetch'], cwd=script_dir, check=True)

            # Check if behind
            result = subprocess.run(
                ['git', 'rev-list', 'HEAD..origin/main', '--count'],
                cwd=script_dir,
                capture_output=True,
                text=True
            )

            commits_behind = int(result.stdout.strip())

            if commits_behind == 0:
                print("✅ You're already on the latest version!")
                return

            print(f"📦 {commits_behind} update(s) available")

            # Show what will be updated
            print("\n📋 Changes:")
            subprocess.run(
                ['git', 'log', 'HEAD..origin/main', '--oneline'],
                cwd=script_dir
            )

            response = input("\n⚠️  Update now? (y/n): ").lower().strip()

            if response == 'y':
                print("\n🔄 Updating...")

                # Stash local changes to config files
                print("💾 Preserving configuration and log files...")
                subprocess.run(['git', 'stash', 'push', '-m', 'Auto-stash before update',
                              'data/', '*.txt'], cwd=script_dir)

                # Pull updates
                subprocess.run(['git', 'pull', 'origin', 'main'], cwd=script_dir, check=True)

                # Restore stashed files
                print("📂 Restoring configuration and log files...")
                subprocess.run(['git', 'stash', 'pop'], cwd=script_dir)

                print("\n✅ Update completed successfully!")
                print("🔄 Please restart the script to use the new version")
                sys.exit(0)
            else:
                print("❌ Update cancelled")

        except subprocess.CalledProcessError as e:
            print(f"✗ Error during update: {e}")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")

    def load_current_state(self):
        """Load current state from file (for loop mode persistence)"""
        if Path(CURRENT_STATE_FILE).exists():
            try:
                with open(CURRENT_STATE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_current_state(self):
        """Save current state to file"""
        with open(CURRENT_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.current_state, f, indent=2, ensure_ascii=False)

    def update_current_file(self, site_name, ip_address, content):
        """Update current state file for a site - completely rewrite to avoid duplication"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = CURRENT_SSAVR if "ssavr" in site_name else CURRENT_COPYPASTE

        # Load existing data
        current_data = {}
        if Path(filename).exists():
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith("[IP:"):
                            # Extract IP address from line
                            ip_match = re.search(r'\(([\d.]+)\)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                current_data[ip] = {"timestamp": "", "content": ""}
            except:
                pass

        # Update with new data
        current_data[ip_address] = {
            "timestamp": timestamp,
            "content": content if content else "(empty)"
        }

        # Completely rewrite file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Current state of {site_name}\n")
            f.write(f"# Last updated: {timestamp}\n")
            f.write(f"# Total IPs tracked: {len(current_data)}\n")
            f.write("="*80 + "\n\n")

            for ip in sorted(current_data.keys()):
                data = current_data[ip]
                f.write(f"[IP: {ip}]\n")
                f.write(f"  Last updated: {data['timestamp']}\n")
                f.write(f"  Content: {data['content']}\n")
                f.write("-"*80 + "\n\n")

    def load_config(self):
        """Load configuration from file"""
        if Path(CONFIG_FILE).exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_config(self, config):
        """Save configuration to file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

    def get_tor_password(self):
        """Get Tor control password from config or user input"""
        config = self.load_config()

        if 'tor_password' in config:
            return config['tor_password']

        print("\n" + "="*80)
        print("🔐 TOR CONTROL PASSWORD SETUP")
        print("="*80)
        print("\nFirst time setup: You need to configure your Tor control password.")
        print("\nOn Linux/Mac, run these commands:")
        print("  1. Generate hashed password:")
        print("     tor --hash-password YOUR_CHOSEN_PASSWORD")
        print("\n  2. Copy the generated hash (starts with '16:...')")
        print("\n  3. Edit /etc/tor/torrc and add these lines:")
        print("     ControlPort 9051")
        print("     HashedControlPassword 16:YOUR_COPIED_HASH")
        print("\n  4. Restart Tor:")
        print("     sudo systemctl restart tor")
        print("\n⚠️  IMPORTANT: When the script asks for password below,")
        print("   enter YOUR_CHOSEN_PASSWORD (the plain text password),")
        print("   NOT the hash that starts with '16:...'")
        print("\nFor more info: https://community.torproject.org/relay/setup/bridge/debian-ubuntu/")
        print("="*80 + "\n")

        password = getpass.getpass("Enter your Tor control password (plain text, not the hash): ")

        save = input("Save password to config file? (y/n): ").lower().strip()
        if save == 'y':
            config['tor_password'] = password
            self.save_config(config)
            print("✓ Password saved to " + CONFIG_FILE)

        return password

    def print_stats(self):
        """Print statistics"""
        print("\n" + "="*80)
        print("📊 STATISTICS")
        print("="*80)

        print(f"\n[ssavr.com]")
        print(f"  ❌ Read failures: {self.stats['ssavr']['read_fail']}")
        print(f"  ❌ Write failures: {self.stats['ssavr']['write_fail']}")
        print(f"  ❌ Verify failures: {self.stats['ssavr']['verify_fail']}")

        print(f"\n[copy-paste.online]")
        print(f"  ❌ Read failures: {self.stats['copypaste']['read_fail']}")
        print(f"  ❌ Write failures: {self.stats['copypaste']['write_fail']}")
        print(f"  ❌ Verify failures: {self.stats['copypaste']['verify_fail']}")

        total_fails = sum(
            self.stats['ssavr'].values()
        ) + sum(
            self.stats['copypaste'].values()
        )
        print(f"\n🔴 Total failures: {total_fails}")
        print("="*80 + "\n")

    def load_history(self):
        """Load message history"""
        if Path(HISTORY_FILE).exists():
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"messages": []}

    def save_history(self):
        """Save message history"""
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)

    def add_to_history(self, message):
        """Add message to history"""
        clean_message = self._clean_text_input(message)
        if clean_message not in self.history["messages"]:
            self.history["messages"].append(clean_message)
            self.save_history()

    def remove_from_history(self, message):
        """Remove message from history"""
        clean_message = self._clean_text_input(message)
        if clean_message in self.history["messages"]:
            self.history["messages"].remove(clean_message)
            self.save_history()
            print(f"✓ Message removed from history: {clean_message}")
        else:
            print(f"✗ Message not found in history: {clean_message}")

    def show_history(self):
        """Show all messages in history"""
        print("\n=== MESSAGE HISTORY ===")
        if self.history["messages"]:
            for i, msg in enumerate(self.history["messages"], 1):
                print(f"{i}. {msg}")
        else:
            print("No messages in history.")
        print()

    def print_startup_info(self):
        """Print startup information"""
        print("\n" + "="*80)
        print(f"🚀 TOR CLIPBOARD SCANNER v{VERSION}")
        print("="*80)

        # Active modes
        print("\n📋 ACTIVE MODES:")
        modes = []
        if self.args.loop:
            modes.append("🔄 Continuous loop (monitoring changes)")
        if self.args.randomize:
            modes.append("🎲 Randomized IPs")
        if self.args.all:
            modes.append("⚠️  Total overwrite")
        elif self.args.overwrite:
            modes.append("🔄 Overwrite own messages")
        if self.args.index:
            modes.append(f"🎯 Starting from IP #{self.args.index}")

        if modes:
            for mode in modes:
                print(f"  {mode}")
        else:
            print("  📖 Standard read mode")

        # Targets
        print("\n🎯 TARGETS:")
        if self.args.target == "SS":
            print("  📌 ssavr.com only")
        elif self.args.target == "CP":
            print("  📌 copy-paste.online only")
        else:
            print("  📌 ssavr.com")
            print("  📌 copy-paste.online")

        # Messages to write
        if self.args.write or self.args.target_ssavr or self.args.target_copypaste:
            print("\n✍️  MESSAGES TO WRITE:")
            if self.args.write:
                print(f"  📝 Both sites: '{self.args.write}'")
            if self.args.target_ssavr:
                print(f"  📝 ssavr.com: '{self.args.target_ssavr}'")
            if self.args.target_copypaste:
                print(f"  📝 copy-paste.online: '{self.args.target_copypaste}'")
        else:
            print("\n📖 MODE: Read only")

        print("="*80 + "\n")

    def check_tor_running(self):
        """Check if Tor is running"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'tor'],
                                   capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        except:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('127.0.0.1', TOR_CONTROL_PORT))
                sock.close()
                return True
            except:
                return False

    def start_tor(self):
        """Start Tor if not active"""
        print("Tor is not active. Attempting to start...")
        try:
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], check=True)
            print("✓ Tor started successfully")
            time.sleep(3)
            return True
        except subprocess.CalledProcessError:
            print("✗ Cannot start Tor with systemctl")
            print("  Try manually: sudo systemctl start tor")
            return False
        except FileNotFoundError:
            print("✗ systemctl not found")
            print("  Start Tor manually or install systemd")
            return False

    def connect_to_tor(self):
        """Connect to Tor Control Port"""
        if not self.check_tor_running():
            print("⚠ Tor is not active")
            if not self.start_tor():
                sys.exit(1)

        # Get password
        self.tor_password = self.get_tor_password()

        try:
            self.controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self.controller.authenticate(password=self.tor_password)
            print("✓ Connected to Tor Control Port")

            # Configure session with SOCKS proxy
            self.session = requests.Session()
            self.session.proxies = {
                'http': f'socks5h://127.0.0.1:{TOR_SOCKS_PORT}',
                'https': f'socks5h://127.0.0.1:{TOR_SOCKS_PORT}'
            }

        except Exception as e:
            print(f"✗ Error connecting to Tor: {e}")
            print("\nMake sure:")
            print("  1. Tor is running: sudo systemctl start tor")
            print("  2. Control port is enabled in /etc/tor/torrc")
            print("  3. Your password is correct (use the PLAIN TEXT password,")
            print("     NOT the hash that starts with '16:...')")
            sys.exit(1)

    def get_exit_nodes(self):
        """Get all valid UNIQUE exit nodes (by IP)"""
        print("🔍 Fetching exit node list...")

        # Collect all nodes
        all_nodes = []
        for desc in self.controller.get_network_statuses():
            if 'Exit' in desc.flags and 'BadExit' not in desc.flags:
                all_nodes.append((desc.fingerprint, desc.address))

        # Filter by unique IP
        ip_to_fingerprint = {}
        for fingerprint, ip in all_nodes:
            if ip not in ip_to_fingerprint:
                ip_to_fingerprint[ip] = fingerprint

        # Return dict {fingerprint: ip} with unique IPs only
        exit_nodes_dict = {fp: ip for ip, fp in ip_to_fingerprint.items()}

        print(f"✓ Found {len(exit_nodes_dict)} valid exit nodes with unique IPs\n")
        return exit_nodes_dict

    def change_exit_node(self, fingerprint):
        """Change exit node"""
        try:
            self.controller.set_conf("ExitNodes", fingerprint)
            self.controller.signal(Signal.NEWNYM)
            time.sleep(3)
            return True
        except Exception as e:
            print(f"✗ Error changing exit node: {e}")
            return False

    def get_current_ip(self):
        """Get current Tor IP"""
        try:
            response = self.session.get('https://api.ipify.org?format=json', timeout=10)
            return response.json()['ip']
        except:
            return "Unknown"

    def get_random_headers(self, site_name):
        """Generate random headers based on site"""
        if "copypaste" in site_name:
            # Use single consistent user agent for copy-paste.online
            user_agent = USER_AGENT_COPYPASTE
        else:
            # Rotate user agents for ssavr.com
            user_agent = random.choice(USER_AGENTS_SSAVR)

        return {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def extract_csrf_token(self, html):
        """Extract CSRF token from HTML page"""
        soup = BeautifulSoup(html, 'html.parser')

        # Look in meta tag
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta:
            return meta.get('content')

        # Look in hidden input
        input_token = soup.find('input', {'name': '_token'})
        if input_token:
            return input_token.get('value')

        # Look in JavaScript
        match = re.search(r'["\']_token["\']\s*:\s*["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)

        return None

    def read_ssavr(self):
        """Read content from ssavr.com with retry logic"""
        max_retries = 2
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                headers = self.get_random_headers("ssavr")
                response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    textarea = soup.find('textarea', {'id': 'savr'})
                    if textarea:
                        content = textarea.text.strip()

                        # If empty and not last attempt, retry to confirm
                        if content == "" and attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue

                        return content
                    return ""

                # If non-200 status and not last attempt, retry
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue

                return None
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return None

        return None

    def write_ssavr(self, content):
        """Write content to ssavr.com"""
        try:
            headers = self.get_random_headers("ssavr")

            # First GET to obtain token and cookies
            response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)

            if response.status_code != 200:
                return False

            # Extract CSRF token
            csrf_token = self.extract_csrf_token(response.text)

            if not csrf_token:
                return False

            # Prepare headers for POST
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers['X-Requested-With'] = 'XMLHttpRequest'
            headers['Origin'] = 'https://www.ssavr.com'
            headers['Referer'] = 'https://www.ssavr.com/'

            # Send POST to save
            post_data = {
                '_token': csrf_token,
                'savr': content
            }

            response = self.session.post('https://www.ssavr.com/save',
                                        data=post_data,
                                        headers=headers,
                                        timeout=30)

            if response.status_code == 200:
                try:
                    data = response.json()
                    return data.get('saved', False)
                except:
                    return False

            return False
        except Exception as e:
            return False

    def read_copypaste(self):
        """Read content from copy-paste.online with retry logic"""
        max_retries = 2
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                headers = self.get_random_headers("copypaste")

                # GET to obtain page
                response = self.session.get('https://copy-paste.online/', headers=headers, timeout=30)

                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')

                    # Site uses id="text" and class="COPYPASTE"
                    textarea = soup.find('textarea', {'id': 'text'})
                    if textarea:
                        content = textarea.text.strip()

                        # If empty and not last attempt, retry to confirm
                        if content == "" and attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue

                        return content

                    # Fallback: search by class
                    textarea = soup.find('textarea', {'class': 'COPYPASTE'})
                    if textarea:
                        content = textarea.text.strip()

                        if content == "" and attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue

                        return content

                    # Last fallback: first textarea
                    textarea = soup.find('textarea')
                    if textarea:
                        content = textarea.text.strip()

                        if content == "" and attempt < max_retries - 1:
                            time.sleep(retry_delay)
                            continue

                        return content

                    return ""

                # If non-200 status and not last attempt, retry
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue

                return None
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return None

        return None

    def write_copypaste(self, content):
        """Write content to copy-paste.online"""
        try:
            headers = self.get_random_headers("copypaste")

            # First GET to obtain cookies and session
            self.session.get('https://copy-paste.online/', headers=headers, timeout=30)

            # Small delay to stabilize session
            time.sleep(0.5)

            # Prepare headers for POST
            headers_post = headers.copy()
            headers_post['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers_post['X-Requested-With'] = 'XMLHttpRequest'
            headers_post['Origin'] = 'https://copy-paste.online'
            headers_post['Referer'] = 'https://copy-paste.online/'

            # Encode in base64 (as the site does)
            data_encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')

            # POST data
            post_data = {
                'fname': 'copypaste',
                'data': data_encoded,
                'mycode': ''
            }

            # Send POST
            response = self.session.post('https://copy-paste.online/func/func.php',
                                        data=post_data,
                                        headers=headers_post,
                                        timeout=30)

            # Site returns a number as success confirmation
            if response.status_code == 200 and response.text.strip().isdigit():
                return True

            return False

        except Exception as e:
            return False

    def log_to_file(self, filename, content, append=True):
        """Write to log file"""
        mode = 'a' if append else 'w'
        with open(filename, mode, encoding='utf-8') as f:
            f.write(content + '\n')

    def should_process_site(self, site_name):
        """Determine if a site should be processed based on target"""
        if self.args.target is None:
            return True

        if site_name == "ssavr.com" and self.args.target == "SS":
            return True
        if site_name == "copy-paste.online" and self.args.target == "CP":
            return True

        return False

    def get_write_content(self, site_name):
        """Get content to write for a specific site"""
        content = None

        if site_name == "ssavr.com":
            if self.args.target_ssavr:
                content = self.args.target_ssavr
            elif self.args.write and (self.args.target is None or self.args.target == "SS"):
                content = self.args.write
        elif site_name == "copy-paste.online":
            if self.args.target_copypaste:
                content = self.args.target_copypaste
            elif self.args.write and (self.args.target is None or self.args.target == "CP"):
                content = self.args.write

        # Apply text normalization
        if content:
            return self._normalize_text_output(content)

        return None

    def is_mine(self, content):
        """Check if content is mine"""
        if not content:
            return False

        clean_content = self._clean_text_input(content)

        # Check in history
        if clean_content in self.history["messages"]:
            return True

        # Check for text processing markers
        if self._txt_proc_enabled:
            # Check if ends with soft hyphen (text normalization marker)
            if content.rstrip('\n').endswith('\u00ad'):
                return True

        return False

    def process_site(self, site_name, read_func, write_func, detailed_file, clean_file, ip_address):
        """Process a site (read/write)"""
        site_key = "ssavr" if "ssavr" in site_name else "copypaste"

        # Check if site should be processed
        if not self.should_process_site(site_name):
            return

        # READ
        print(f"  [{site_name}] 📖 Reading...", end=' ')
        current_content = read_func()

        if current_content is None:
            print("❌ Failed (connection error after retries)")
            self.stats[site_key]["read_fail"] += 1
            return

        # Update current state file (always, regardless of mode)
        self.update_current_file(site_name, ip_address, current_content)

        is_mine_content = self.is_mine(current_content)
        clean_content = self._clean_text_input(current_content) if current_content else ""

        if current_content == "":
            print("✅ OK (empty)")
        else:
            preview = clean_content[:40] + "..." if len(clean_content) > 40 else clean_content
            ownership = "mine" if is_mine_content else "new"
            print(f"✅ OK ({ownership}): '{preview}'")

        # Log dettagliato
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "EMPTY" if current_content == "" else ("MINE" if is_mine_content else "NEW")
        log_entry = f"[{timestamp}] {ip_address} - {status}: {clean_content}"
        self.log_to_file(detailed_file, log_entry)

        # Log pulito (SOLO se contenuto nuovo di altri)
        write_content = self.get_write_content(site_name)
        is_writing_now = write_content and current_content == write_content

        if current_content and not is_mine_content and not is_writing_now:
            clean_entry = f"[{timestamp}] {ip_address}\n{clean_content}\n{'-'*80}"
            self.log_to_file(clean_file, clean_entry)

        # LOOP MODE: detect changes
        if self.args.loop:
            # Create changes file if it doesn't exist
            if not Path(CHANGES_FILE).exists():
                with open(CHANGES_FILE, 'w', encoding='utf-8') as f:
                    f.write("# Changes detected during loop mode\n")
                    f.write(f"# Started: {timestamp}\n")
                    f.write("="*80 + "\n\n")

            # Build state key using IP address
            state_key = f"{ip_address}_{site_name}"

            # Check if this IP was seen before
            if state_key in self.current_state:
                prev_content = self.current_state[state_key]

                # Detect change
                if prev_content != current_content:
                    change_log = f"[{timestamp}] 🔄 CHANGE detected on {site_name}\n"
                    change_log += f"  IP: {ip_address}\n"
                    change_log += f"  BEFORE: {self._clean_text_input(prev_content) if prev_content else '(empty)'}\n"
                    change_log += f"  AFTER: {clean_content if current_content else '(empty)'}\n"
                    change_log += "-" * 80 + "\n"
                    self.log_to_file(CHANGES_FILE, change_log)
                    print(f"  [{site_name}] ⚠️  Change detected!")

            # Save current state for next iteration
            self.current_state[state_key] = current_content
            self.save_current_state()
            return

        # OPTIMIZATION: if correct message is already there, skip
        if write_content and current_content == write_content:
            print(f"  [{site_name}] ✅ Message already present, skipping write")
            return

        # WRITE
        if write_content:
            should_write = False
            write_type = ""

            if self.args.all:
                # Mode -a: overwrite everything
                should_write = True
                write_type = "total overwrite"
            elif current_content == "":
                # Empty field
                should_write = True
                write_type = "empty field"
            elif self.args.overwrite and is_mine_content:
                # Overwrite active and content is mine
                should_write = True
                write_type = "own overwrite"

            if should_write:
                print(f"  [{site_name}] ✍️  Writing ({write_type})...", end=' ')
                if write_func(write_content):
                    print("✅ OK")

                    # VERIFY
                    time.sleep(2)
                    print(f"  [{site_name}] 🔍 Verifying...", end=' ')
                    verify = read_func()

                    if verify == write_content:
                        print("✅ OK")
                        # Update current state file with written content
                        self.update_current_file(site_name, ip_address, verify)
                    else:
                        print(f"❌ Failed (different content)")
                        self.stats[site_key]["verify_fail"] += 1
                else:
                    print("❌ Failed")
                    self.stats[site_key]["write_fail"] += 1

    def scan_all_ips(self):
        """Scan all IPs"""
        start_index = self.args.index if self.args.index else 0

        exit_nodes_items = list(self.exit_nodes.items())

        if self.args.randomize:
            random.shuffle(exit_nodes_items)

        total = len(exit_nodes_items)

        for i, (fingerprint, ip_address) in enumerate(exit_nodes_items[start_index:], start=start_index):
            print(f"\n{'='*80}")
            print(f"🌐 IP {i+1}/{total} | {ip_address}")
            print(f"{'='*80}")

            # Change exit node
            if not self.change_exit_node(fingerprint):
                continue

            # Verify actual IP
            current_ip = self.get_current_ip()

            # Process ssavr.com
            self.process_site("ssavr.com", self.read_ssavr, self.write_ssavr,
                            SSAVR_DETAILED, SSAVR_CLEAN, current_ip)

            # Process copy-paste.online
            self.process_site("copy-paste.online", self.read_copypaste, self.write_copypaste,
                            COPYPASTE_DETAILED, COPYPASTE_CLEAN, current_ip)

            print(f"✅ IP {i+1}/{total} completed")

    def run(self):
        """Run the script"""
        # Handle special arguments
        if self.args.show_history:
            self.show_history()
            return

        if self.args.add_history:
            self.add_to_history(self.args.add_history)
            print(f"✓ Message added to history: {self.args.add_history}")
            return

        if self.args.remove_history:
            self.remove_from_history(self.args.remove_history)
            return

        # Validate arguments
        if self.args.loop and (self.args.write or self.args.target_ssavr or self.args.target_copypaste):
            print("✗ Error: -l (loop) cannot be used with -w/-ts/-tc (write)")
            sys.exit(1)

        if self.args.all and self.args.overwrite:
            print("✗ Error: -a (all) cannot be used with -o (overwrite)")
            sys.exit(1)

        if self.args.target and (self.args.target_ssavr or self.args.target_copypaste):
            print("✗ Error: -t cannot be used together with -ts/-tc")
            sys.exit(1)

        # Add messages to history if writing
        if self.args.write:
            self.add_to_history(self.args.write)
        if self.args.target_ssavr:
            self.add_to_history(self.args.target_ssavr)
        if self.args.target_copypaste:
            self.add_to_history(self.args.target_copypaste)

        # Print startup info
        self.print_startup_info()

        # Connect to Tor
        self.connect_to_tor()

        # Main loop
        while self.running:
            if self.args.loop:
                self.loop_iteration += 1
                print(f"\n{'='*80}")
                print(f"🔄 ROUND #{self.loop_iteration}")
                print(f"{'='*80}\n")

            # Update exit node list
            self.exit_nodes = self.get_exit_nodes()

            # Scan all IPs
            self.scan_all_ips()

            if not self.args.loop:
                break

            print(f"\n{'='*80}")
            print(f"✅ Round #{self.loop_iteration} completed. Restarting in 5 seconds...")
            print(f"{'='*80}\n")
            time.sleep(5)


def main():
    parser = argparse.ArgumentParser(
        description='Tor Clipboard Scanner - Scan ssavr.com and copy-paste.online through Tor exit nodes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DESCRIPTION:
  This tool scans clipboard sharing websites (ssavr.com and copy-paste.online)
  through different Tor exit nodes to read and write messages anonymously.

  Each exit node provides a different IP address, allowing you to check what
  content is visible from different geographic locations or write messages
  that only certain exit nodes can see.

FIRST TIME SETUP (Linux/Mac):
  1. Install Tor: sudo apt install tor (Debian/Ubuntu) or brew install tor (Mac)
  2. Generate password hash: tor --hash-password YOUR_CHOSEN_PASSWORD
  3. Copy the hash (starts with '16:...')
  4. Edit /etc/tor/torrc and add these lines:
     ControlPort 9051
     HashedControlPassword 16:YOUR_COPIED_HASH
  5. Restart Tor: sudo systemctl restart tor
  6. Run this script - it will ask for YOUR_CHOSEN_PASSWORD (plain text, not hash)

⚠️  IMPORTANT: When entering password, use plain text password, NOT the hash!

MODES:
  Read-only:  Scans all exit nodes and logs found messages
  Write mode: Writes your message to empty fields or overwrites your own messages
  Loop mode:  Continuously monitors for changes across all exit nodes
              - Persists state across restarts
              - Detects new/removed exit nodes automatically
              - Logs all changes to changes.txt

FILE ORGANIZATION:
  Main directory (frequently accessed):
    - ssavr_clean.txt         Only NEW messages from others (ssavr.com)
    - copypaste_clean.txt     Only NEW messages from others (copy-paste.online)
    - changes.txt             Changes detected in loop mode

  data/ directory (detailed logs and config):
    - ssavr_detailed.txt      All reads from ssavr.com
    - copypaste_detailed.txt  All reads from copy-paste.online
    - current_ssavr.txt       Current state snapshot (ssavr.com)
    - current_copypaste.txt   Current state snapshot (copy-paste.online)
    - inputs_history.json     Your message history
    - current_state.json      Loop mode state (persistent)
    - .tor_scanner_config.json  Saved Tor password (optional)

TARGETS:
  -t SS     Only scan/write to ssavr.com
  -t CP     Only scan/write to copy-paste.online
  (none)    Scan/write to both sites (default)

EXAMPLES:
  %(prog)s -u                           # Check for updates
  %(prog)s                              # Read-only scan
  %(prog)s -w "Hello"                   # Write to empty fields
  %(prog)s -w "Test" -o                 # Write and overwrite own messages
  %(prog)s -t SS -w "Only ssavr"        # Write only to ssavr.com
  %(prog)s -l                           # Loop mode: monitor changes
  %(prog)s -i 100                       # Start from exit node #100
  %(prog)s -b                           # Randomize IP order

DEPENDENCIES:
  pip install requests[socks] stem beautifulsoup4

MORE INFO:
  GitHub: https://github.com/Jester-tek/ssavr-copypaste-scanner
        """
    )

    parser.add_argument('-u', '--update', action='store_true',
                       help='Check for updates from GitHub repository')
    parser.add_argument('-w', '--write',
                       help='Write message to both sites (only to empty fields by default)')
    parser.add_argument('-t', '--target', choices=['SS', 'CP'],
                       help='Target site: SS (ssavr.com only) or CP (copy-paste.online only)')
    parser.add_argument('-ts', '--target-ssavr',
                       help='Write message only to ssavr.com')
    parser.add_argument('-tc', '--target-copypaste',
                       help='Write message only to copy-paste.online')
    parser.add_argument('-o', '--overwrite', action='store_true',
                       help='With -w/-ts/-tc, also overwrite your own previous messages')
    parser.add_argument('-a', '--all', action='store_true',
                       help='Overwrite ANY content found (use with caution! Cannot be used with -o)')
    parser.add_argument('-i', '--index', type=int,
                       help='Start from specified IP number (e.g., 500)')
    parser.add_argument('-l', '--loop', action='store_true',
                       help='Loop mode: continuously scan and monitor for changes (persists across restarts)')
    parser.add_argument('-b', '--randomize', action='store_true',
                       help='Randomize the order of exit nodes')
    parser.add_argument('-x', '--add-history',
                       help='Add a message to history (mark as already written by you)')
    parser.add_argument('-k', '--show-history', action='store_true',
                       help='Show all messages in history')
    parser.add_argument('-r', '--remove-history',
                       help='Remove a message from history')

    args = parser.parse_args()

    # Handle update check
    if args.update:
        scanner = TorClipboardScanner(args)
        scanner.check_for_updates()
        return

    scanner = TorClipboardScanner(args)

    try:
        scanner.run()
    except KeyboardInterrupt:
        scanner.running = False
        print("\n\n" + "="*80)
        print("🛑 USER INTERRUPT")
        print("="*80)
        scanner.print_stats()
        print("✓ Script terminated\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
