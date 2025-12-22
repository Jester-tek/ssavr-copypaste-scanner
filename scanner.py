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
import ipaddress
from datetime import datetime
from pathlib import Path
import requests
from stem import Signal
from stem.control import Controller
from bs4 import BeautifulSoup

VERSION = "4.0.0"
REPO_URL = "https://github.com/Jester-tek/ssavr-copypaste-scanner"

TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
CONFIG_FILE = "data/.tor_scanner_config.json"

DATA_DIR = "data"
DEBUG_LOG = f"{DATA_DIR}/debug.log"
HISTORY_FILE = f"{DATA_DIR}/inputs_history.json"
CURRENT_STATE_FILE = f"{DATA_DIR}/current_state.json"

SSAVR_CLEAN = "ssavr_clean.txt"
COPYPASTE_CLEAN = "copypaste_clean.txt"
CHANGES_FILE = "changes.txt"

SSAVR_DETAILED = f"{DATA_DIR}/ssavr_detailed.txt"
COPYPASTE_DETAILED = f"{DATA_DIR}/copypaste_detailed.txt"
CURRENT_SSAVR = f"{DATA_DIR}/current_ssavr.txt"
CURRENT_COPYPASTE = f"{DATA_DIR}/current_copypaste.txt"

USER_AGENTS_SSAVR = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

USER_AGENT_COPYPASTE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def clean_text(text):
    if not text:
        return ""
    invisible_chars = ['\u00ad', '\u200b', '\u200c', '\u200d', '\ufeff']
    for char in invisible_chars:
        text = text.replace(char, '')
    text = re.sub(r'\s+', ' ', text).strip()
    return text


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


class TorClipboardScanner:
    def __init__(self, args):
        self.args = args
        self.socks_port = args.socks_port if args.socks_port else TOR_SOCKS_PORT
        self.control_port = args.control_port if args.control_port else TOR_CONTROL_PORT
        Path(DATA_DIR).mkdir(exist_ok=True)
        self.history = self.load_history()
        self.exit_nodes = []
        self.session = None
        self.controller = None
        self.tor_password = None
        self.current_state = self.load_current_state()
        self.loop_iteration = 0
        self.clean_cache = {"ssavr": {}, "copypaste": {}}
        self.load_clean_cache()
        self.stats = {
            "ssavr": {"read_fail": 0, "write_fail": 0, "verify_fail": 0},
            "copypaste": {"read_fail": 0, "write_fail": 0, "verify_fail": 0}
        }
        self.running = True
        self._txt_proc_enabled = not os.path.exists(f"{DATA_DIR}/.disable_advanced_features")

    def load_clean_cache(self):
        if Path(SSAVR_CLEAN).exists():
            try:
                with open(SSAVR_CLEAN, 'r', encoding='utf-8') as f:
                    current_ip = None
                    for line in f:
                        if line.startswith('['):
                            ip = extract_ip_from_text(line)
                            if ip:
                                current_ip = ip
                        elif current_ip and line.strip() and not line.startswith('-'):
                            self.clean_cache["ssavr"][current_ip] = line.strip()
                            current_ip = None
            except Exception as e:
                self.debug_log(f"Error loading ssavr clean cache: {e}")
        if Path(COPYPASTE_CLEAN).exists():
            try:
                with open(COPYPASTE_CLEAN, 'r', encoding='utf-8') as f:
                    current_ip = None
                    for line in f:
                        if line.startswith('['):
                            ip = extract_ip_from_text(line)
                            if ip:
                                current_ip = ip
                        elif current_ip and line.strip() and not line.startswith('-'):
                            self.clean_cache["copypaste"][current_ip] = line.strip()
                            current_ip = None
            except Exception as e:
                self.debug_log(f"Error loading copypaste clean cache: {e}")
        print(f"📋 Loaded clean cache: {len(self.clean_cache['ssavr'])} ssavr, {len(self.clean_cache['copypaste'])} copypaste")

    def debug_log(self, message, data=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
            if data:
                f.write(f"  Data: {data}\n")

    def _normalize_text_output(self, text):
        if not self._txt_proc_enabled or not text:
            return text
        if text and not text.endswith('\n'):
            text = text + '\u00ad'
        return text

    def check_for_updates(self):
        print("\n" + "="*80)
        print("🔄 CHECKING FOR UPDATES")
        print("="*80)
        try:
            script_path = os.path.abspath(__file__)
            script_dir = os.path.dirname(script_path)
            result = subprocess.run(['git', 'rev-parse', '--git-dir'], cwd=script_dir, capture_output=True, text=True)
            if result.returncode != 0:
                print("✗ Not a git repository. Please clone from GitHub:")
                print(f"  git clone {REPO_URL}")
                return
            print("📡 Fetching latest version from GitHub...")
            subprocess.run(['git', 'fetch'], cwd=script_dir, check=True)
            result = subprocess.run(['git', 'rev-list', 'HEAD..origin/main', '--count'], cwd=script_dir, capture_output=True, text=True)
            commits_behind = int(result.stdout.strip())
            if commits_behind == 0:
                print("✅ You're already on the latest version!")
                return
            print(f"📦 {commits_behind} update(s) available")
            print("\n📋 Changes:")
            subprocess.run(['git', 'log', 'HEAD..origin/main', '--oneline'], cwd=script_dir)
            response = input("\n⚠️  Update now? (y/n): ").lower().strip()
            if response == 'y':
                print("\n🔄 Updating...")
                print("💾 Preserving configuration and log files...")
                subprocess.run(['git', 'stash', 'push', '-m', 'Auto-stash before update', 'data/', '*.txt'], cwd=script_dir)
                subprocess.run(['git', 'pull', 'origin', 'main'], cwd=script_dir, check=True)
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
        if Path(CURRENT_STATE_FILE).exists():
            try:
                with open(CURRENT_STATE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_current_state(self):
        with open(CURRENT_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.current_state, f, indent=2, ensure_ascii=False)

    def update_current_file(self, site_name, ip_address, content):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = CURRENT_SSAVR if "ssavr" in site_name else CURRENT_COPYPASTE
        current_data = {}
        if Path(filename).exists():
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith("[IP:"):
                            extracted_ip = extract_ip_from_text(line)
                            if extracted_ip:
                                current_data[extracted_ip] = {"timestamp": "", "content": ""}
            except:
                pass
        current_data[ip_address] = {"timestamp": timestamp, "content": content if content else "(empty)"}
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
        if Path(CONFIG_FILE).exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_config(self, config):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)

    def get_tor_password(self):
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
        print(f"     ControlPort {self.control_port}")
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
        total_fails = sum(self.stats['ssavr'].values()) + sum(self.stats['copypaste'].values())
        print(f"\n🔴 Total failures: {total_fails}")
        print("="*80 + "\n")

    def load_history(self):
        if Path(HISTORY_FILE).exists():
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {"messages": []}

    def save_history(self):
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)

    def add_to_history(self, message):
        clean_message = clean_text(message)
        if clean_message not in self.history["messages"]:
            self.history["messages"].append(clean_message)
            self.save_history()

    def remove_from_history(self, message):
        clean_message = clean_text(message)
        if clean_message in self.history["messages"]:
            self.history["messages"].remove(clean_message)
            self.save_history()
            print(f"✓ Message removed from history: {clean_message}")
        else:
            print(f"✗ Message not found in history: {clean_message}")

    def show_history(self):
        print("\n=== MESSAGE HISTORY ===")
        if self.history["messages"]:
            for i, msg in enumerate(self.history["messages"], 1):
                print(f"{i}. {msg}")
        else:
            print("No messages in history.")
        print()

    def print_startup_info(self):
        print("\n" + "="*80)
        print(f"🚀 TOR CLIPBOARD SCANNER v{VERSION}")
        print("="*80)
        print(f"\n🔧 TOR CONFIGURATION:")
        print(f"  SOCKS Port: {self.socks_port}")
        print(f"  Control Port: {self.control_port}")
        print("\n📋 ACTIVE MODES:")
        modes = []
        if self.args.single:
            modes.append(f"🎯 Single IP mode: #{self.args.single}")
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
        print("\n🎯 TARGETS:")
        if self.args.target == "SS":
            print("  📌 ssavr.com only")
        elif self.args.target == "CP":
            print("  📌 copy-paste.online only")
        else:
            print("  📌 ssavr.com")
            print("  📌 copy-paste.online")
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
        try:
            result = subprocess.run(['systemctl', 'is-active', 'tor'], capture_output=True, text=True)
            return result.stdout.strip() == 'active'
        except:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('127.0.0.1', self.control_port))
                sock.close()
                return True
            except:
                return False

    def start_tor(self):
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
        if not self.check_tor_running():
            print("⚠ Tor is not active")
            if not self.start_tor():
                sys.exit(1)
        self.tor_password = self.get_tor_password()
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate(password=self.tor_password)
            print(f"✓ Connected to Tor Control Port ({self.control_port})")
        except Exception as e:
            print(f"✗ Error connecting to Tor: {e}")
            print("\nMake sure:")
            print("  1. Tor is running: sudo systemctl start tor")
            print(f"  2. Control port {self.control_port} is enabled in /etc/tor/torrc")
            print("  3. Your password is correct (use the PLAIN TEXT password,")
            print("     NOT the hash that starts with '16:...')")
            sys.exit(1)

    def create_fresh_session(self):
        if self.session:
            self.session.close()
        self.session = requests.Session()
        self.session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }

    def get_exit_nodes(self):
        print("🔍 Fetching exit node list...")
        all_nodes = []
        for desc in self.controller.get_network_statuses():
            if 'Exit' in desc.flags and 'BadExit' not in desc.flags:
                all_nodes.append((desc.fingerprint, desc.address))
        ip_to_fingerprint = {}
        for fingerprint, ip in all_nodes:
            if ip not in ip_to_fingerprint:
                ip_to_fingerprint[ip] = fingerprint
        exit_nodes_dict = {fp: ip for ip, fp in ip_to_fingerprint.items()}
        print(f"✓ Found {len(exit_nodes_dict)} valid exit nodes with unique IPs\n")
        return exit_nodes_dict

    def verify_ip_via_external(self, expected_ip=None, timeout=30):
        start_time = time.time()
        while (time.time() - start_time) < timeout:
            try:
                response = self.session.get('https://ifconfig.co/ip', timeout=5)
                if response.status_code == 200:
                    detected_ip = response.text.strip()
                    if expected_ip:
                        if detected_ip == expected_ip:
                            return detected_ip
                        else:
                            time.sleep(2)
                            continue
                    else:
                        return detected_ip
            except:
                time.sleep(2)
                continue
        return None

    def change_exit_node(self, fingerprint, expected_ip):
        try:
            self.controller.set_conf("ExitNodes", f"${fingerprint}")
            self.controller.set_conf("StrictNodes", "1")
            self.controller.signal(Signal.NEWNYM)
            self.create_fresh_session()
            verified_ip = self.verify_ip_via_external(expected_ip, timeout=30)
            if verified_ip:
                if verified_ip != expected_ip:
                    self.debug_log(f"IP mismatch: expected {expected_ip}, got {verified_ip}")
                return True
            else:
                self.debug_log(f"Failed to verify IP for {fingerprint}")
                return False
        except Exception as e:
            print(f"✗ Error changing exit node: {e}")
            self.debug_log(f"Change exit node error", str(e))
            return False

    def get_random_headers(self, site_name):
        if "copypaste" in site_name:
            user_agent = USER_AGENT_COPYPASTE
        else:
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

    def read_ssavr(self):
        max_retries = 2
        retry_delay = 2
        for attempt in range(max_retries + 1):
            try:
                headers = self.get_random_headers("ssavr")
                response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)
                if response.status_code != 200:
                    self.debug_log(f"Ssavr non-200: {response.status_code}", f"Headers: {response.headers}, Body: {response.text[:500]}")
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    textarea = soup.find('textarea', {'id': 'savr'})
                    if textarea:
                        content = textarea.text.strip()
                        if content == "" and attempt < max_retries:
                            print(f"(empty, retry {attempt + 1}/{max_retries})...", end=' ')
                            time.sleep(retry_delay)
                            continue
                        return content
                    if attempt < max_retries:
                        print(f"(no textarea, retry {attempt + 1}/{max_retries})...", end=' ')
                        time.sleep(retry_delay)
                        continue
                    return ""
                else:
                    if attempt < max_retries:
                        print(f"(error {response.status_code}, retry {attempt + 1}/{max_retries})...", end=' ')
                        time.sleep(retry_delay)
                        continue
                    return None
            except Exception as e:
                self.debug_log("Ssavr read exception", str(e))
                if attempt < max_retries:
                    print(f"(exception, retry {attempt + 1}/{max_retries})...", end=' ')
                    time.sleep(retry_delay)
                    continue
                return None
        return None

    def write_ssavr(self, content):
        try:
            headers = self.get_random_headers("ssavr")
            response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)
            if response.status_code != 200:
                return False
            csrf_token = self.extract_csrf_token(response.text)
            if not csrf_token:
                return False
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
            self.debug_log("Ssavr write exception", str(e))
            return False

    def read_copypaste(self):
        max_retries = 2
        retry_delay = 2
        for attempt in range(max_retries + 1):
            try:
                headers = self.get_random_headers("copypaste")
                response = self.session.get('https://copy-paste.online/', headers=headers, timeout=30)
                if "user agents" in response.text.lower() or "premium plan" in response.text.lower():
                    self.debug_log("CopyPaste rate limit detected", response.text[:500])
                    print("  ⚠️  CopyPaste rate limit detected")
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    textarea = soup.find('textarea', {'id': 'text'})
                    if not textarea:
                        textarea = soup.find('textarea', {'class': 'COPYPASTE'})
                    if not textarea:
                        textarea = soup.find('textarea')
                    if textarea:
                        content = textarea.text.strip()
                        if content == "" and attempt < max_retries:
                            print(f"(empty, retry {attempt + 1}/{max_retries})...", end=' ')
                            time.sleep(retry_delay)
                            continue
                        return content
                    if attempt < max_retries:
                        print(f"(no textarea, retry {attempt + 1}/{max_retries})...", end=' ')
                        time.sleep(retry_delay)
                        continue
                    return ""
                else:
                    if attempt < max_retries:
                        print(f"(error {response.status_code}, retry {attempt + 1}/{max_retries})...", end=' ')
                        time.sleep(retry_delay)
                        continue
                    return None
            except Exception as e:
                self.debug_log("CopyPaste read exception", str(e))
                if attempt < max_retries:
                    print(f"(exception, retry {attempt + 1}/{max_retries})...", end=' ')
                    time.sleep(retry_delay)
                    continue
                return None
        return None

    def write_copypaste(self, content):
        try:
            headers = self.get_random_headers("copypaste")
            self.session.get('https://copy-paste.online/', headers=headers, timeout=30)
            time.sleep(0.5)
            headers_post = headers.copy()
            headers_post['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            headers_post['X-Requested-With'] = 'XMLHttpRequest'
            headers_post['Origin'] = 'https://copy-paste.online'
            headers_post['Referer'] = 'https://copy-paste.online/'
            data_encoded = base64.b64encode(content.encode('utf-8')).decode('ascii')
            post_data = {'fname': 'copypaste', 'data': data_encoded, 'mycode': ''}
            response = self.session.post('https://copy-paste.online/func/func.php', data=post_data, headers=headers_post, timeout=30)
            if response.status_code == 200 and response.text.strip().isdigit():
                return True
            return False
        except Exception as e:
            self.debug_log("CopyPaste write exception", str(e))
            return False

    def log_to_file(self, filename, content, append=True):
        mode = 'a' if append else 'w'
        with open(filename, mode, encoding='utf-8') as f:
            f.write(content + '\n')

    def should_process_site(self, site_name):
        if self.args.target is None:
            return True
        if site_name == "ssavr.com" and self.args.target == "SS":
            return True
        if site_name == "copy-paste.online" and self.args.target == "CP":
            return True
        return False

    def get_write_content(self, site_name):
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
        if content:
            return self._normalize_text_output(content)
        return None

    def is_mine(self, content):
        if not content:
            return False
        clean_content = clean_text(content)
        if clean_content in self.history["messages"]:
            return True
        if self._txt_proc_enabled and content.endswith('\u00ad'):
            return True
        return False

    def should_write_to_clean(self, site_key, ip_address, content):
        clean_content = clean_text(content)
        if ip_address in self.clean_cache[site_key]:
            cached_content = self.clean_cache[site_key][ip_address]
            if clean_text(cached_content) == clean_content:
                return False
        return True

    def process_site(self, site_name, read_func, write_func, detailed_file, clean_file, ip_address):
        site_key = "ssavr" if "ssavr" in site_name else "copypaste"
        if not self.should_process_site(site_name):
            return
        print(f"  [{site_name}] 📖 Reading...", end=' ')
        current_content = read_func()
        if current_content is None:
            print("❌ Failed (connection error after retries)")
            self.stats[site_key]["read_fail"] += 1
            return
        self.update_current_file(site_name, ip_address, current_content)
        is_mine_content = self.is_mine(current_content)
        clean_content = clean_text(current_content)
        if current_content == "":
            print("✅ OK (empty)")
        else:
            preview = clean_content[:40] + "..." if len(clean_content) > 40 else clean_content
            ownership = "mine" if is_mine_content else "new"
            print(f"✅ OK ({ownership}): '{preview}'")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "EMPTY" if current_content == "" else ("MINE" if is_mine_content else "NEW")
        log_entry = f"[{timestamp}] {ip_address} - {status}: {clean_content}"
        self.log_to_file(detailed_file, log_entry)
        write_content = self.get_write_content(site_name)
        is_writing_now = write_content and clean_text(current_content) == clean_text(write_content)
        if current_content and not is_mine_content and not is_writing_now:
            if self.should_write_to_clean(site_key, ip_address, clean_content):
                clean_entry = f"[{timestamp}] {ip_address}\n{clean_content}\n{'-'*80}"
                self.log_to_file(clean_file, clean_entry)
                self.clean_cache[site_key][ip_address] = clean_content
            else:
                print(f"  [{site_name}] 💾 Already logged in clean file, skipping")
        if self.args.loop:
            if not Path(CHANGES_FILE).exists():
                with open(CHANGES_FILE, 'w', encoding='utf-8') as f:
                    f.write("# Changes detected during loop mode\n")
                    f.write(f"# Started: {timestamp}\n")
                    f.write("="*80 + "\n\n")
            state_key = f"{ip_address}_{site_name}"
            if state_key in self.current_state:
                prev_content = self.current_state[state_key]
                if clean_text(prev_content) != clean_text(current_content):
                    change_log = f"[{timestamp}] 🔄 CHANGE detected on {site_name}\n"
                    change_log += f"  IP: {ip_address}\n"
                    change_log += f"  BEFORE: {clean_text(prev_content) if prev_content else '(empty)'}\n"
                    change_log += f"  AFTER: {clean_content if current_content else '(empty)'}\n"
                    change_log += "-" * 80 + "\n"
                    self.log_to_file(CHANGES_FILE, change_log)
                    print(f"  [{site_name}] ⚠️  Change detected!")
            self.current_state[state_key] = current_content
            self.save_current_state()
            return
        if write_content and clean_text(current_content) == clean_text(write_content):
            print(f"  [{site_name}] ✅ Message already present, skipping write")
            return
        if write_content:
            should_write = False
            write_type = ""
            if self.args.all:
                should_write = True
                write_type = "total overwrite"
            elif current_content == "":
                should_write = True
                write_type = "empty field"
            elif self.args.overwrite and is_mine_content:
                should_write = True
                write_type = "own overwrite"
            if should_write:
                print(f"  [{site_name}] ✍️  Writing ({write_type})...", end=' ')
                if write_func(write_content):
                    print("✅ OK")
                    time.sleep(2)
                    print(f"  [{site_name}] 🔍 Verifying...", end=' ')
                    verify = read_func()
                    if verify and clean_text(verify) == clean_text(write_content):
                        print("✅ OK")
                        self.update_current_file(site_name, ip_address, verify)
                    else:
                        print(f"❌ Failed (different content)")
                        self.stats[site_key]["verify_fail"] += 1
                else:
                    print("❌ Failed")
                    self.stats[site_key]["write_fail"] += 1

    def scan_all_ips(self):
        start_index = (self.args.index - 1) if self.args.index and self.args.index > 0 else 0
        exit_nodes_items = list(self.exit_nodes.items())
        if self.args.randomize:
            random.shuffle(exit_nodes_items)
        total = len(exit_nodes_items)
        if self.args.single:
            if self.args.single < 1 or self.args.single > total:
                print(f"✗ Error: IP index {self.args.single} out of range (1-{total})")
                return
            idx = self.args.single - 1
            fingerprint, ip_address = exit_nodes_items[idx]
            print(f"\n{'='*80}")
            print(f"🌐 IP {self.args.single}/{total} | {ip_address}")
            print(f"{'='*80}")
            if not self.change_exit_node(fingerprint, ip_address):
                print("✗ Failed to set exit node")
                return
            self.process_site("ssavr.com", self.read_ssavr, self.write_ssavr, SSAVR_DETAILED, SSAVR_CLEAN, ip_address)
            time.sleep(1)
            self.process_site("copy-paste.online", self.read_copypaste, self.write_copypaste, COPYPASTE_DETAILED, COPYPASTE_CLEAN, ip_address)
            print(f"✅ IP {self.args.single}/{total} completed")
            return
        for i, (fingerprint, ip_address) in enumerate(exit_nodes_items[start_index:], start=start_index + 1):
            print(f"\n{'='*80}")
            print(f"🌐 IP {i}/{total} | {ip_address}")
            print(f"{'='*80}")
            if not self.change_exit_node(fingerprint, ip_address):
                continue
            self.process_site("ssavr.com", self.read_ssavr, self.write_ssavr, SSAVR_DETAILED, SSAVR_CLEAN, ip_address)
            time.sleep(1)
            self.process_site("copy-paste.online", self.read_copypaste, self.write_copypaste, COPYPASTE_DETAILED, COPYPASTE_CLEAN, ip_address)
            print(f"✅ IP {i}/{total} completed")

    def run(self):
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
        if self.args.single and self.args.index:
            print("✗ Error: -s (single) cannot be used with -i (index)")
            sys.exit(1)
        if self.args.single and self.args.loop:
            print("✗ Error: -s (single) cannot be used with -l (loop)")
            sys.exit(1)
        if self.args.single and self.args.randomize:
            print("✗ Error: -s (single) cannot be used with -b (randomize)")
            sys.exit(1)
        if self.args.loop and (self.args.write or self.args.target_ssavr or self.args.target_copypaste):
            print("✗ Error: -l (loop) cannot be used with -w/-ts/-tc (write)")
            sys.exit(1)
        if self.args.all and self.args.overwrite:
            print("✗ Error: -a (all) cannot be used with -o (overwrite)")
            sys.exit(1)
        if self.args.target and (self.args.target_ssavr or self.args.target_copypaste):
            print("✗ Error: -t cannot be used together with -ts/-tc")
            sys.exit(1)
        if self.args.write:
            self.add_to_history(self.args.write)
        if self.args.target_ssavr:
            self.add_to_history(self.args.target_ssavr)
        if self.args.target_copypaste:
            self.add_to_history(self.args.target_copypaste)
        self.print_startup_info()
        self.connect_to_tor()
        while self.running:
            if self.args.loop:
                self.loop_iteration += 1
                print(f"\n{'='*80}")
                print(f"🔄 ROUND #{self.loop_iteration}")
                print(f"{'='*80}\n")
            self.exit_nodes = self.get_exit_nodes()
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

FIRST TIME SETUP (Linux/Mac):
  1. Install Tor: sudo apt install tor (Debian/Ubuntu) or brew install tor (Mac)
  2. Generate password hash: tor --hash-password YOUR_CHOSEN_PASSWORD
  3. Copy the hash (starts with '16:...')
  4. Edit /etc/tor/torrc and add:
     ControlPort 9051
     HashedControlPassword 16:YOUR_COPIED_HASH
  5. Restart Tor: sudo systemctl restart tor
  6. Run this script - enter YOUR_CHOSEN_PASSWORD (plain text, not hash)

QUOTES IN ARGUMENTS:
  Quotes are REQUIRED when your message contains spaces.

  Examples:
    ✅ python3 scanner.py -w "Hello world"     (spaces = quotes required)
    ✅ python3 scanner.py -w Hello             (no spaces = quotes optional)
    ✅ python3 scanner.py -w 'Hello world'     (single quotes work too)
    ❌ python3 scanner.py -w Hello world       (ERROR: only reads "Hello")

TOR BROWSER MODE:
  To use Tor Browser instead of system Tor:
  %(prog)s --socks-port 9150 --control-port 9151 [other options]

FILE ORGANIZATION:
  Main directory:
    - ssavr_clean.txt, copypaste_clean.txt, changes.txt
  data/ directory:
    - Detailed logs, config, state files
    - Create data/.disable_advanced_features (empty file) to disable text processing

EXAMPLES:
  %(prog)s -u                           # Check for updates
  %(prog)s                              # Read-only scan
  %(prog)s -s 139                       # Scan ONLY IP #139
  %(prog)s -i 100                       # Start from IP #100
  %(prog)s -w "Hello" -a                # Write to all IPs (overwrite everything)
  %(prog)s -l                           # Loop mode: monitor changes
  %(prog)s -t SS -w "Only SS"           # Write only to ssavr.com
  %(prog)s -t CP -w "Only CP"           # Write only to copy-paste.online
  %(prog)s -ts "Hi SS" -tc "Hi CP"      # Different messages on two sites
  %(prog)s --socks-port 9150 --control-port 9151 -s 1  # Use Tor Browser

DEPENDENCIES:
  pip install requests[socks] stem beautifulsoup4

MORE INFO:
  GitHub: https://github.com/Jester-tek/ssavr-copypaste-scanner
        """
    )
    parser.add_argument('-u', '--update', action='store_true', help='Check for updates from GitHub')
    parser.add_argument('--socks-port', type=int, help='Tor SOCKS port (default: 9050, Tor Browser: 9150)')
    parser.add_argument('--control-port', type=int, help='Tor Control port (default: 9051, Tor Browser: 9151)')
    parser.add_argument('-w', '--write', help='Write message to both sites')
    parser.add_argument('-t', '--target', choices=['SS', 'CP'], help='Target: SS (ssavr.com) or CP (copy-paste.online)')
    parser.add_argument('-ts', '--target-ssavr', help='Write message only to ssavr.com')
    parser.add_argument('-tc', '--target-copypaste', help='Write message only to copy-paste.online')
    parser.add_argument('-o', '--overwrite', action='store_true', help='Also overwrite your own previous messages')
    parser.add_argument('-a', '--all', action='store_true', help='Overwrite ANY content (⚠️ dangerous!)')
    parser.add_argument('-i', '--index', type=int, help='Start from IP number (1-based, e.g., -i 100 starts from IP #100)')
    parser.add_argument('-s', '--single', type=int, help='Scan ONLY the specified IP number and stop (1-based, e.g., -s 139)')
    parser.add_argument('-l', '--loop', action='store_true', help='Loop mode: continuously monitor for changes')
    parser.add_argument('-b', '--randomize', action='store_true', help='Randomize exit node order')
    parser.add_argument('-x', '--add-history', help='Add message to history')
    parser.add_argument('-k', '--show-history', action='store_true', help='Show all messages in history')
    parser.add_argument('-r', '--remove-history', help='Remove message from history')
    args = parser.parse_args()
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
