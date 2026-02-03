import time
import getpass
import requests
import subprocess
import socket
import os
import atexit
from stem import Signal
from stem.control import Controller
from . import config, utils

class TorManager:
    def __init__(self, socks_port=None, control_port=None):
        self.socks_port = socks_port or config.SCANNER_SOCKS_PORT
        self.control_port = control_port or config.SCANNER_CONTROL_PORT
        self.controller = None
        self.session = None
        self.tor_password = None
        self.tor_process = None  # Our dedicated Tor daemon
        self.using_dedicated_tor = False
        
        # Register cleanup on exit
        atexit.register(self.shutdown_scanner_tor)

    def create_scanner_torrc(self):
        """Create dedicated torrc for scanner - doesn't touch system Tor."""
        config.SCANNER_TOR_DIR.mkdir(parents=True, exist_ok=True)
        config.SCANNER_TOR_DATA.mkdir(parents=True, exist_ok=True)
        
        torrc_content = f"""# Scanner-specific Tor instance - DOES NOT AFFECT SYSTEM TOR
SocksPort {config.SCANNER_SOCKS_PORT}
ControlPort {config.SCANNER_CONTROL_PORT}
DataDirectory {config.SCANNER_TOR_DATA}
CookieAuthentication 1
Log notice file {config.SCANNER_TOR_DIR / 'tor.log'}

# Performance optimizations for scanning
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600
NewCircuitPeriod 15
"""
        with open(config.SCANNER_TORRC, 'w') as f:
            f.write(torrc_content)
        
        utils.debug_log(f"Created scanner torrc at {config.SCANNER_TORRC}")
        return True

    def start_scanner_tor(self):
        """Start dedicated Tor instance for scanner only."""
        print("🔄 Starting dedicated Tor instance for scanner...")
        
        # Check if already running on scanner port
        if self._check_port_open(config.SCANNER_SOCKS_PORT):
            print("   ⚠️  Scanner Tor port already in use, will try to connect")
            return True
        
        # Create torrc
        self.create_scanner_torrc()
        
        try:
            self.tor_process = subprocess.Popen(
                ['tor', '-f', str(config.SCANNER_TORRC)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for Tor to bootstrap
            print("   ⏳ Waiting for Tor to bootstrap (this may take 30-60s)...")
            for i in range(60):
                time.sleep(1)
                if self._check_port_open(config.SCANNER_SOCKS_PORT):
                    print(f"   ✓ Scanner Tor started (port {config.SCANNER_SOCKS_PORT})")
                    self.using_dedicated_tor = True
                    return True
                if self.tor_process.poll() is not None:
                    # Process exited
                    stderr = self.tor_process.stderr.read().decode()
                    print(f"   ✗ Tor failed to start: {stderr[:200]}")
                    return False
            
            print("   ✗ Tor bootstrap timeout")
            return False
            
        except FileNotFoundError:
            print("   ✗ Tor binary not found. Install with: sudo apt install tor")
            return False
        except Exception as e:
            print(f"   ✗ Error starting Tor: {e}")
            return False

    def shutdown_scanner_tor(self):
        """Shutdown dedicated Tor instance."""
        if self.tor_process and self.tor_process.poll() is None:
            print("🔄 Shutting down scanner's Tor instance...")
            self.tor_process.terminate()
            try:
                self.tor_process.wait(timeout=10)
                print("   ✓ Scanner Tor stopped")
            except subprocess.TimeoutExpired:
                self.tor_process.kill()
                print("   ⚠️ Scanner Tor force-killed")
        
        # Cleanup controller
        if self.controller:
            try:
                self.controller.close()
            except:
                pass

    def _check_port_open(self, port):
        """Check if a port is open."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(('127.0.0.1', port))
            sock.close()
            return True
        except:
            return False

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
        """Connect to scanner's dedicated Tor instance."""
        # Start dedicated scanner Tor (doesn't affect system Tor)
        if not self.start_scanner_tor():
            print("✗ Failed to start scanner's Tor instance")
            return False
        
        # Wait a bit for control port to be ready
        time.sleep(2)
        
        try:
            self.controller = Controller.from_port(port=self.control_port)
            
            # Use cookie authentication (no password needed for our own instance)
            cookie_path = config.SCANNER_TOR_DATA / "control_auth_cookie"
            if cookie_path.exists():
                with open(cookie_path, 'rb') as f:
                    cookie = f.read()
                self.controller.authenticate(cookie)
            else:
                # Fallback to password if cookie not available
                self.tor_password = self.get_tor_password()
                self.controller.authenticate(password=self.tor_password)
            
            print(f"✓ Connected to Scanner Tor Control Port ({self.control_port})")
            return True
        except Exception as e:
            print(f"✗ Error connecting to Scanner Tor: {e}")
            utils.debug_log(f"Tor connection error: {e}")
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
            # NEWNYM removed - setting ExitNodes is sufficient, new circuits will use it
            # This avoids Tor's 10-second rate limit on NEWNYM signals
            
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

    def cleanup(self):
        """Reset Tor config to defaults. Call on script exit to not affect other apps."""
        try:
            if self.controller and self.controller.is_alive():
                self.controller.reset_conf("ExitNodes")
                self.controller.reset_conf("StrictNodes")
                utils.debug_log("Tor config cleaned up (ExitNodes/StrictNodes reset)")
        except Exception as e:
            utils.debug_log(f"Cleanup error: {e}")
