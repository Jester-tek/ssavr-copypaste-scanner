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
from datetime import datetime
from pathlib import Path
import requests
from stem import Signal
from stem.control import Controller
from bs4 import BeautifulSoup

# Tor Configuration
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
CONFIG_FILE = ".tor_scanner_config.json"

# Log files
HISTORY_FILE = "inputs_history.json"
SSAVR_DETAILED = "ssavr_detailed.txt"
SSAVR_CLEAN = "ssavr_clean.txt"
COPYPASTE_DETAILED = "copypaste_detailed.txt"
COPYPASTE_CLEAN = "copypaste_clean.txt"
CHANGES_FILE = "changes.txt"

# Random user agents for anonymity
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


class TorClipboardScanner:
    def __init__(self, args):
        self.args = args
        self.history = self.load_history()
        self.exit_nodes = []
        self.session = None
        self.controller = None
        self.tor_password = None

        # State for loop mode
        self.previous_state = {}  # {ip: {"ssavr": content, "copypaste": content}}
        self.loop_iteration = 0

        # Statistics
        self.stats = {
            "ssavr": {"read_fail": 0, "write_fail": 0, "verify_fail": 0},
            "copypaste": {"read_fail": 0, "write_fail": 0, "verify_fail": 0}
        }

        self.running = True

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
        print("  1. Generate hashed password: tor --hash-password YOUR_PASSWORD")
        print("  2. Edit /etc/tor/torrc and add: HashedControlPassword YOUR_HASH")
        print("  3. Restart Tor: sudo systemctl restart tor")
        print("\nFor more info: https://community.torproject.org/relay/setup/bridge/debian-ubuntu/")
        print("="*80 + "\n")
        
        password = getpass.getpass("Enter your Tor control password: ")
        
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
        if message not in self.history["messages"]:
            self.history["messages"].append(message)
            self.save_history()

    def remove_from_history(self, message):
        """Remove message from history"""
        if message in self.history["messages"]:
            self.history["messages"].remove(message)
            self.save_history()
            print(f"✓ Message removed from history: {message}")
        else:
            print(f"✗ Message not found in history: {message}")

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
        print("🚀 TOR CLIPBOARD SCANNER")
        print("="*80)
        
        # Active modes
        print("\n📋 ACTIVE MODES:")
        modes = []
        if self.args.loop:
            modes.append("🔄 Continuous loop")
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
        import subprocess
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
        import subprocess
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
            print("  3. Your password is correct")
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

    def get_random_headers(self):
        """Generate random headers"""
        return {
            'User-Agent': random.choice(USER_AGENTS),
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
        """Read content from ssavr.com"""
        try:
            headers = self.get_random_headers()
            response = self.session.get('https://www.ssavr.com/', headers=headers, timeout=30)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                textarea = soup.find('textarea', {'id': 'savr'})
                if textarea:
                    return textarea.text.strip()
                return ""
            return None
        except Exception as e:
            return None

    def write_ssavr(self, content):
        """Write content to ssavr.com"""
        try:
            headers = self.get_random_headers()

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
        """Read content from copy-paste.online"""
        try:
            headers = self.get_random_headers()

            # GET to obtain page
            response = self.session.get('https://copy-paste.online/', headers=headers, timeout=30)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')

                # Site uses id="text" and class="COPYPASTE"
                textarea = soup.find('textarea', {'id': 'text'})
                if textarea:
                    return textarea.text.strip()

                # Fallback: search by class
                textarea = soup.find('textarea', {'class': 'COPYPASTE'})
                if textarea:
                    return textarea.text.strip()

                # Last fallback: first textarea
                textarea = soup.find('textarea')
                if textarea:
                    return textarea.text.strip()

                return ""
            return None
        except Exception as e:
            return None

    def write_copypaste(self, content):
        """Write content to copy-paste.online"""
        try:
            headers = self.get_random_headers()

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
        if site_name == "ssavr.com":
            if self.args.target_ssavr:
                return self.args.target_ssavr
            elif self.args.write and (self.args.target is None or self.args.target == "SS"):
                return self.args.write
        elif site_name == "copy-paste.online":
            if self.args.target_copypaste:
                return self.args.target_copypaste
            elif self.args.write and (self.args.target is None or self.args.target == "CP"):
                return self.args.write

        return None

    def process_site(self, site_name, read_func, write_func, detailed_file, clean_file, ip_info):
        """Process a site (read/write)"""
        site_key = "ssavr" if "ssavr" in site_name else "copypaste"
        
        # Check if site should be processed
        if not self.should_process_site(site_name):
            return

        # READ
        print(f"  [{site_name}] 📖 Reading...", end=' ')
        current_content = read_func()

        if current_content is None:
            print("❌ Failed (connection error)")
            self.stats[site_key]["read_fail"] += 1
            return

        is_mine = current_content in self.history["messages"] if current_content else False
        
        if current_content == "":
            print("✅ OK (empty)")
        else:
            preview = current_content[:40] + "..." if len(current_content) > 40 else current_content
            ownership = "mine" if is_mine else "new"
            print(f"✅ OK ({ownership}): '{preview}'")

        # Detailed log
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "EMPTY" if current_content == "" else ("MINE" if is_mine else "NEW")
        log_entry = f"[{timestamp}] {ip_info} - {status}: {current_content}"
        self.log_to_file(detailed_file, log_entry)

        # Clean log (ONLY if new content)
        write_content = self.get_write_content(site_name)
        is_writing_now = write_content and current_content == write_content

        if current_content and not is_mine and not is_writing_now:
            clean_entry = f"[{timestamp}] {ip_info}\n{current_content}\n{'-'*80}"
            self.log_to_file(clean_file, clean_entry)

        # LOOP MODE: detect changes
        if self.args.loop:
            ip_key = ip_info
            if ip_key not in self.previous_state:
                self.previous_state[ip_key] = {}

            prev_content = self.previous_state[ip_key].get(site_name, None)

            if prev_content is not None and prev_content != current_content:
                change_log = f"[{timestamp}] 🔄 CHANGE {ip_info} on {site_name}:\n"
                change_log += f"  BEFORE: {prev_content}\n"
                change_log += f"  AFTER: {current_content}\n"
                change_log += "-" * 80 + "\n"
                self.log_to_file(CHANGES_FILE, change_log)
                print(f"  [{site_name}] ⚠️  Change detected!")

            self.previous_state[ip_key][site_name] = current_content
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
            elif self.args.overwrite and is_mine:
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
            ip_info = f"IP #{i+1} ({current_ip})"

            # Process ssavr.com
            self.process_site("ssavr.com", self.read_ssavr, self.write_ssavr,
                            SSAVR_DETAILED, SSAVR_CLEAN, ip_info)

            # Process copy-paste.online
            self.process_site("copy-paste.online", self.read_copypaste, self.write_copypaste,
                            COPYPASTE_DETAILED, COPYPASTE_CLEAN, ip_info)

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
  2. Generate password hash: tor --hash-password YOUR_PASSWORD
  3. Edit /etc/tor/torrc and add: HashedControlPassword YOUR_HASH
  4. Add to torrc: ControlPort 9051
  5. Restart Tor: sudo systemctl restart tor
  6. Run this script - it will ask for the password on first run

MODES:
  Read-only:  Scans all exit nodes and logs found messages
  Write mode: Writes your message to empty fields or overwrites your own messages
  Loop mode:  Continuously monitors for changes across all exit nodes

TARGETS:
  -t SS     Only scan/write to ssavr.com
  -t CP     Only scan/write to copy-paste.online
  (none)    Scan/write to both sites (default)

WRITE OPTIONS:
  -w MSG            Write same message to both sites
  -ts MSG           Write message only to ssavr.com
  -tc MSG           Write message only to copy-paste.online
  -o                Overwrite your own previous messages
  -a                Overwrite ANY content found (use with caution!)

HISTORY MANAGEMENT:
  The script keeps track of messages you've written in inputs_history.json
  This prevents logging your own messages as "new content"
  
  -x MSG            Add message to history (mark as "yours")
  -k                Show all messages in history
  -r MSG            Remove message from history

OUTPUT FILES:
  ssavr_detailed.txt          All reads from ssavr.com (empty/mine/new)
  ssavr_clean.txt             Only NEW messages from ssavr.com
  copypaste_detailed.txt      All reads from copy-paste.online (empty/mine/new)
  copypaste_clean.txt         Only NEW messages from copy-paste.online
  changes.txt                 Changes detected in loop mode
  inputs_history.json         Your written messages history
  .tor_scanner_config.json    Saved Tor password (optional)

CONTROLS:
  Ctrl+C                Interrupt and show statistics

EXAMPLES:
  %(prog)s                              # Read-only scan of all exit nodes
  %(prog)s -w "Hello World"             # Write to empty fields on both sites
  %(prog)s -w "Test" -o                 # Write and overwrite your messages
  %(prog)s -w "Test" -a                 # Overwrite EVERYTHING (dangerous!)
  %(prog)s -t SS -w "Only ssavr"        # Write only to ssavr.com
  %(prog)s -t CP -w "Only copypaste"    # Write only to copy-paste.online
  %(prog)s -ts "Hi SS" -tc "Hi CP"      # Different messages per site
  %(prog)s -l                           # Loop mode: monitor changes
  %(prog)s -i 100                       # Start from exit node #100
  %(prog)s -w "Test" -b                 # Write in random order
  %(prog)s -x "Old message"             # Add to history without writing
  %(prog)s -k                           # Show message history
  %(prog)s -r "Message"                 # Remove from history

DEPENDENCIES:
  pip install requests[socks] stem beautifulsoup4
  
  Or from requirements.txt:
  pip install -r requirements.txt

MORE INFO:
  GitHub: https://github.com/yourusername/tor-clipboard-scanner
  Tor Setup: https://community.torproject.org/relay/setup/bridge/debian-ubuntu/
        """
    )

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
                       help='Loop mode: continuously scan and monitor for changes')
    parser.add_argument('-b', '--randomize', action='store_true',
                       help='Randomize the order of exit nodes')
    parser.add_argument('-x', '--add-history',
                       help='Add a message to history (mark as already written by you)')
    parser.add_argument('-k', '--show-history', action='store_true',
                       help='Show all messages in history')
    parser.add_argument('-r', '--remove-history',
                       help='Remove a message from history')

    args = parser.parse_args()

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