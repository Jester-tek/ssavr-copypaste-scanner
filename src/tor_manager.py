import time
import getpass
import requests
import subprocess
import socket
from stem import Signal
from stem.control import Controller
from . import config, utils

class TorManager:
    def __init__(self, socks_port=None, control_port=None):
        self.socks_port = socks_port or config.DEFAULT_SOCKS_PORT
        self.control_port = control_port or config.DEFAULT_CONTROL_PORT
        self.controller = None
        self.session = None
        self.tor_password = None

    def check_tor_running(self):
        try:
            result = subprocess.run(['systemctl', 'is-active', 'tor'], capture_output=True, text=True)
            if result.stdout.strip() == 'active':
                return True
        except:
            pass
        
        # Fallback: check open port
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

    def get_tor_password(self):
        loaded_config = config.load_config()
        if 'tor_password' in loaded_config:
            return loaded_config['tor_password']
        
        print("\n" + "="*80)
        print("🔐 TOR CONTROL PASSWORD SETUP")
        print("="*80)
        print("\nFirst time setup: You need to configure your Tor control password.")
        print("\nOn Linux/Mac, run these commands:")
        print("  1. Generate hashed password:")
        print("     tor --hash-password YOUR_CHOSEN_PASSWORD")
        print("\n  2. Copy the hash (starts with '16:...')")
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
            loaded_config['tor_password'] = password
            config.save_config(loaded_config)
            print("✓ Password saved to configuration")
        return password

    def connect(self):
        if not self.check_tor_running():
            print("⚠ Tor is not active")
            if not self.start_tor():
                return False
                
        self.tor_password = self.get_tor_password()
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate(password=self.tor_password)
            print(f"✓ Connected to Tor Control Port ({self.control_port})")
            return True
        except Exception as e:
            print(f"✗ Error connecting to Tor: {e}")
            print("\nMake sure:")
            print("  1. Tor is running: sudo systemctl start tor")
            print(f"  2. Control port {self.control_port} is enabled in /etc/tor/torrc")
            print("  3. Your password is correct (use the PLAIN TEXT password)")
            return False

    def get_new_session(self):
        """Returns a new session object configured with SOCKS proxy."""
        session = requests.Session()
        session.proxies = {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }
        return session

    def create_fresh_session(self):
        if self.session:
            self.session.close()
        self.session = self.get_new_session()
        return self.session

    def get_exit_nodes(self):
        print("🔍 Fetching exit node list...")
        all_nodes = []
        try:
            for desc in self.controller.get_network_statuses():
                if 'Exit' in desc.flags and 'BadExit' not in desc.flags:
                    all_nodes.append((desc.fingerprint, desc.address))
            
            # Deduplicate by IP
            ip_to_fingerprint = {}
            for fingerprint, ip in all_nodes:
                if ip not in ip_to_fingerprint:
                    ip_to_fingerprint[ip] = fingerprint
            
            exit_nodes_dict = {fp: ip for ip, fp in ip_to_fingerprint.items()}
            print(f"✓ Found {len(exit_nodes_dict)} valid exit nodes with unique IPs\n")
            return exit_nodes_dict
        except Exception as e:
            print(f"✗ Error fetching exit nodes: {e}")
            utils.debug_log(f"Error fetching exit nodes: {e}")
            return {}

    def verify_ip_via_external(self, expected_ip=None, timeout=None, verbose=False):
        timeout = timeout or config.TOR_CONNECT_TIMEOUT
        if not self.session:
            self.create_fresh_session()
            
        providers = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://ifconfig.me/ip',
            'https://checkip.amazonaws.com',
            'https://ifconfig.co/ip'
        ]
        import random
        
        attempt = 0
        start_time = time.time()
        if verbose:
            print(f"   🔄 Verifying IP {expected_ip}...", end="", flush=True)
        
        while (time.time() - start_time) < timeout:
            # Shuffle providers to load balance / avoid patterns
            random.shuffle(providers)
            
            for url in providers:
                if (time.time() - start_time) >= timeout:
                    break
                
                attempt += 1
                try:
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        detected_ip = response.text.strip()
                        if expected_ip:
                            if detected_ip == expected_ip:
                                elapsed = time.time() - start_time
                                if verbose: print(f" ✓ ({elapsed:.1f}s, {attempt} attempts)")
                                return detected_ip
                            else:
                                # IP mismatch, maybe Tor hasn't switched yet
                                if verbose: print(".", end="", flush=True)
                                continue
                        else:
                            if verbose: print(f" ✓")
                            return detected_ip
                except Exception as e:
                    if verbose: print("x", end="", flush=True)
                    pass
            
            time.sleep(1) # Wait a bit before retrying the loop
        
        if verbose: print(f" ✗ (timeout after {timeout}s)")
        return None

    def change_exit_node(self, fingerprint, expected_ip, verbose=False):
        try:
            self.controller.set_conf("ExitNodes", f"${fingerprint}")
            self.controller.set_conf("StrictNodes", "1")
            self.controller.signal(Signal.NEWNYM)
            
            self.create_fresh_session()
            
            verified_ip = self.verify_ip_via_external(expected_ip, timeout=config.TOR_CONNECT_TIMEOUT, verbose=verbose)
            if verified_ip:
                if verified_ip != expected_ip:
                    utils.debug_log(f"IP mismatch: expected {expected_ip}, got {verified_ip}")
                return True
            else:
                utils.debug_log(f"Failed to verify IP for {fingerprint}")
                return False
        except Exception as e:
            # print(f"✗ Error changing exit node: {e}") # Reduce verbosity in main output
            utils.debug_log(f"Change exit node error: {e}")
            return False

    def reset_circuit(self):
        """Reset Tor circuit when stuck. Called after consecutive failures."""
        try:
            print("   🔄 Resetting Tor circuit (was stuck)...", end="", flush=True)
            # Clear ExitNodes constraint
            self.controller.reset_conf("ExitNodes")
            self.controller.reset_conf("StrictNodes")
            
            # Send NEWNYM twice with delay
            self.controller.signal(Signal.NEWNYM)
            time.sleep(3)
            self.controller.signal(Signal.NEWNYM)
            
            # Wait for Tor to stabilize
            time.sleep(10)
            
            # Create fresh session
            self.create_fresh_session()
            
            print(" ✓ (reset complete)")
            return True
        except Exception as e:
            print(f" ✗ (reset failed: {e})")
            utils.debug_log(f"Reset circuit error: {e}")
            return False
