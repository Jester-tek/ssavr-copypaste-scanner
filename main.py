#!/usr/bin/env python3
"""
Tor Clipboard Scanner
Scans ssavr.com and copy-paste.online through Tor exit nodes
Refactored Version
"""

import sys
import argparse
import time
import random
import signal
from pathlib import Path
from datetime import datetime

# Import our modules
# Assuming src is in the same directory or python path
try:
    from src import config, utils, storage, tor_manager, updater, proxy_manager
    from src.sites.ssavr import SsavrClient
    from src.sites.copypaste import CopyPasteClient
    from src.display import SplitScreenDisplay, TorDisplayAdapter, ProxyDisplayAdapter
    import requests
    from concurrent.futures import ThreadPoolExecutor
except ImportError:
    # If running directly from the project root without installation
    sys.path.append(str(Path(__file__).parent))
    from src import config, utils, storage, tor_manager, updater, proxy_manager
    from src.sites.ssavr import SsavrClient
    from src.sites.copypaste import CopyPasteClient
    from src.display import SplitScreenDisplay, TorDisplayAdapter, ProxyDisplayAdapter
    import requests
    from concurrent.futures import ThreadPoolExecutor

class ScannerApp:
    def __init__(self, args):
        self.args = args
        self.running = True
        self.storage = storage.StorageManager()
        self.tor = tor_manager.TorManager(
            socks_port=args.socks_port,
            control_port=args.control_port
        )
        self.clients = {
            "ssavr": SsavrClient(self.tor.get_new_session),
            "copypaste": CopyPasteClient(self.tor.get_new_session)
        }
        self.stats = {
            "ssavr": {"read_fail": 0, "write_fail": 0, "verify_fail": 0, "proxy_success": 0},
            "copypaste": {"read_fail": 0, "write_fail": 0, "verify_fail": 0, "proxy_success": 0}
        }
        self.ip_skips = 0
        self.proxy_manager = proxy_manager.ProxyManager()
        self.proxy_executor = None
        self.start_time = time.time()
        
        signal.signal(signal.SIGINT, self.handle_interrupt)

    def print_report(self):
        print("\n\n" + "="*80)
        print("📊 FINAL SCAN REPORT")
        print("="*80)
        
        # Calculate duration
        if hasattr(self, 'start_time'):
            elapsed = time.time() - self.start_time
            mins, secc = divmod(int(elapsed), 60)
            print(f"⏱  Duration: {mins}m {secc}s")

        # Display stats
        print(f"\n[ssavr.com]")
        print(f"  ❌ Read failures: {self.stats['ssavr']['read_fail']}")
        print(f"  ❌ Write failures: {self.stats['ssavr']['write_fail']}")
        print(f"  ❌ Verify failures: {self.stats['ssavr']['verify_fail']}")

        print(f"\n[copy-paste.online]")
        print(f"  ❌ Read failures: {self.stats['copypaste']['read_fail']}")
        print(f"  ❌ Write failures: {self.stats['copypaste']['write_fail']}")
        print(f"  ❌ Verify failures: {self.stats['copypaste']['verify_fail']}")

        total_fails = sum(self.stats[s][k] for s in self.stats for k in self.stats[s] if k != 'proxy_success')
        
        print(f"\n[Infrastructure]")
        print(f"  🔄 Total Tor restarts: {self.tor.restarts}")
        print(f"  ⏩ Total IPs skipped: {self.ip_skips}")

        print(f"\n🔴 Total site failures: {total_fails}")
        print("="*80)
        print("\n✓ Script terminated")

    def handle_interrupt(self, sig, frame):
        print("\n🛑 USER INTERRUPT (Stopping gracefully...)")
        self.print_report()
        self.running = False

    def print_stats(self):
        print("\n" + "="*80)
        print("📊 STATISTICS")
        print("="*80)
        for key in ["ssavr", "copypaste"]:
            name = key.replace("copypaste", "copy-paste.online").replace("ssavr", "ssavr.com")
            print(f"\n[{name}]")
            print(f"  ❌ Read failures: {self.stats[key]['read_fail']}")
            print(f"  ❌ Write failures: {self.stats[key]['write_fail']}")
            print(f"  ❌ Verify failures: {self.stats[key]['verify_fail']}")
        
        total_fails = sum(self.stats['ssavr'].values()) + sum(self.stats['copypaste'].values()) - self.stats['ssavr']['proxy_success'] - self.stats['copypaste']['proxy_success']
        print(f"\n[Infrastructure]")
        print(f"  🔄 Total Tor restarts: {self.tor.restarts}")
        print(f"  ⏩ Total IPs skipped: {self.ip_skips}")
        print(f"  ⚡ Proxy successes: SS({self.stats['ssavr']['proxy_success']}), CP({self.stats['copypaste']['proxy_success']})")
        
        print(f"\n🔴 Total site failures: {total_fails}")
        print("="*80 + "\n")

    def print_startup_info(self):
        print("\n" + "="*80)
        print(f"🚀 TOR CLIPBOARD SCANNER v{config.VERSION}")
        print("="*80)
        print(f"\n🔧 TOR CONFIGURATION:")
        print(f"  SOCKS Port: {self.tor.socks_port}")
        print(f"  Control Port: {self.tor.control_port}")
        print("\n📋 ACTIVE MODES:")
        modes = []
        if self.args.single: modes.append(f"🎯 Single IP mode: #{self.args.single}")
        if self.args.loop: modes.append("🔄 Continuous loop (monitoring changes)")
        if self.args.randomize: modes.append("🎲 Randomized IPs")
        if self.args.all: modes.append("⚠️  Total overwrite")
        elif self.args.overwrite: modes.append("🔄 Overwrite own messages")
        if self.args.index: modes.append(f"🎯 Starting from IP #{self.args.index}")
        
        if modes:
            for mode in modes: print(f"  {mode}")
        else:
            print("  📖 Standard read mode")

        print("\n🎯 TARGETS:")
        if self.args.target == "SS": print("  📌 ssavr.com only")
        elif self.args.target == "CP": print("  📌 copy-paste.online only")
        else:
            print("  📌 ssavr.com")
            print("  📌 copy-paste.online")

        # Determine if we are writing anything
        w_ssavr, w_cp = self.get_write_contents()
        if w_ssavr or w_cp:
            print("\n✍️  MESSAGES TO WRITE:")
            if w_ssavr == w_cp and w_ssavr:
                print(f"  📝 Both sites: '{w_ssavr[:50]}...'")
            else:
                if w_ssavr: print(f"  📝 ssavr.com: '{w_ssavr[:50]}...'")
                if w_cp: print(f"  📝 copy-paste.online: '{w_cp[:50]}...'")
        else:
            print("\n📖 MODE: Read only")
        print("="*80 + "\n")

    def get_write_contents(self):
        """
        Determine what content to write for each site.
        Applies logic: Specific target args > General write arg.
        Normalized (markers added) if applicable.
        """
        # Load from files if needed (already handled in main() argument parsing usually, 
        # but let's assume args contain the raw strings now)
        
        content_ssavr = None
        content_cp = None

        # General write arg
        if self.args.write:
            content_ssavr = self.args.write
            content_cp = self.args.write

        # Specific overrides
        if self.args.target_ssavr:
            content_ssavr = self.args.target_ssavr
        if self.args.target_copypaste:
            content_cp = self.args.target_copypaste

        # Filter by target site arg
        if self.args.target == "SS":
            content_cp = None
        elif self.args.target == "CP":
            content_ssavr = None

        # Normalize (add marker)
        # Note: If content is None, normalize returns None (or "")
        return utils.normalize_text_output(content_ssavr), utils.normalize_text_output(content_cp)

    def process_site_for_ip(self, site_key, client, ip_address, write_content, display_manager=None):
        # Set immediate status to show parallelism
        if display_manager:
            display_manager.update(site_key, "Connecting...", "🔄")
            
        site_name = client.get_name()
        
        # Helper to update display if available
        def update_status(msg, icon=None):
            if display_manager:
                display_manager.update(site_key, msg, icon)
        
        # Check if we should skip this site
        if self.args.target == "SS" and site_key != "ssavr": 
            update_status("Skipped", "⏭")
            return
        if self.args.target == "CP" and site_key != "copypaste": 
            update_status("Skipped", "⏭")
            return

        update_status("Reading...", "📖")
        
        current_content = client.read()
        
        if current_content is None:
            update_status("Failed", "❌")
            self.stats[site_key]["read_fail"] += 1
            return

        # Update current view files
        self.storage.update_current_view_file(site_name, ip_address, current_content)

        clean_content = utils.clean_text(current_content)
        is_mine = utils.is_mine(current_content, self.storage.history["messages"])
        ownership = "mine" if is_mine else "new"
        
        if current_content == "":
            update_status("✅ Found: [Empty]", "✅")
            if display_manager and isinstance(display_manager, ProxyDisplayManager):
                 # Standard logging if it's the proxy
                 display_manager.log(f"   [{ip_address}] [{site_name}] Found: [Empty]")
            elif display_manager:
                 display_manager.log(f"   [{ip_address}] [{site_name}] Found: [Empty]")
        else:
            # Show a longer preview as requested
            preview = clean_content[:60] + "..." if len(clean_content) > 60 else clean_content
            ownership_str = " (MINE)" if is_mine else " [NEW]"
            update_status(f"✅ Found{ownership_str}: '{preview}'", "✅")
            if display_manager: display_manager.log(f"   [{ip_address}] [{site_name}] Found{ownership_str}: '{preview}'")

        # Log detailed
        from datetime import datetime as dt_class
        timestamp = dt_class.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "EMPTY" if current_content == "" else ("MINE" if is_mine else "NEW")
        self.storage.log_to_file(
            config.SSAVR_DETAILED if site_key == "ssavr" else config.COPYPASTE_DETAILED, 
            f"[{timestamp}] {ip_address} - {status}: {clean_content}"
        )

        # Logic for writing to clean file
        is_writing_same = write_content and utils.clean_text(write_content) == clean_content
        
        if current_content and not is_mine and not is_writing_same:
            cached = self.storage.clean_cache[site_key].get(ip_address)
            if not cached or utils.clean_text(cached) != clean_content:
                clean_entry = f"[{timestamp}] {ip_address}\n{clean_content}\n{'-'*80}"
                self.storage.log_to_file(
                    config.SSAVR_CLEAN if site_key == "ssavr" else config.COPYPASTE_CLEAN, 
                    clean_entry
                )
                self.storage.clean_cache[site_key][ip_address] = clean_content

        # Change detection (Global)
        state_key = f"{ip_address}_{site_name}"
        prev_content = self.storage.current_state.get(state_key)
        prev_clean = utils.clean_text(prev_content) if prev_content else ""
        
        # Only log changes between two NON-EMPTY contents
        if prev_clean and clean_content and prev_clean != clean_content:
            change_log = f"[{timestamp}] 🔄 CHANGE detected on {site_name}\n"
            change_log += f"  IP: {ip_address}\n"
            change_log += f"  BEFORE: {utils.clean_text(prev_content)}\n"
            change_log += f"  AFTER: {clean_content}\n"
            change_log += "-" * 80 + "\n"
            self.storage.log_to_file(config.CHANGES_FILE, change_log)
            # Only show alert if loop mode or explicitly requested, otherwise it might be noisy? 
            # Actually user asked for it to update "always". 
            # Let's show the alert but maybe shorter or just log it. 
            # Keeping existing behavior but global.
            update_status("⚠️ Change detected!", "⚠️")
            time.sleep(2) # Show the alert briefly
        
        self.storage.current_state[state_key] = current_content
        self.storage.save_current_state()
            # return  <-- Removed to allow fall-through to Write Logic

        # Write Logic
        if write_content:
            # If content matches what we want to write, skip
            if utils.clean_text(current_content) == utils.clean_text(write_content):
                update_status("Message already present", "✅")
                return

            should_write = False
            write_type = ""
            
            if self.args.all:
                should_write = True
                write_type = "total overwrite"
            elif current_content == "":
                should_write = True
                write_type = "empty field"
            elif self.args.overwrite and is_mine:
                should_write = True
                write_type = "own overwrite"

            if should_write:
                # Log what we are overwriting
                if display_manager:
                     if current_content == "":
                         display_manager.log(f"   [{ip_address}] [{site_name}] Overwriting [Empty] with new message")
                     elif is_mine:
                         display_manager.log(f"   [{ip_address}] [{site_name}] Overwriting [Own Message]")
                     else:
                         # Truncate the content preview to 80 chars
                         preview_rm = clean_content[:80] + "..." if len(clean_content) > 80 else clean_content
                         display_manager.log(f"[bold red]🗑  [{ip_address}] [{site_name}] Removing:[/bold red] {preview_rm}")

                update_status(f"Writing ({write_type})...", "✍️")
                if client.write(write_content):
                    update_status("Verifying...", "🔍")
                    time.sleep(2)
                    verify_content = client.read()
                    
                    if verify_content and utils.clean_text(verify_content) == utils.clean_text(write_content):
                        update_status("Done (Written & Verified)", "✅")
                        self.storage.update_current_view_file(site_name, ip_address, verify_content)
                    else:
                        update_status("Verification Failed", "❌")
                        self.stats[site_key]["verify_fail"] += 1
                        return False
                else:
                    update_status("Write Failed", "❌")
                    self.stats[site_key]["write_fail"] += 1
                    return False
        return True # If no write was performed, or if write was successful

    def process_ip_with_clients(self, ip_address, clients_dict, w_ssavr, w_cp, display_manager, sequential=False):
        """Processes both sites for a given IP address using the provided clients."""
        # Reset sessions first
        try:
            clients_dict["ssavr"].reset_session()
            clients_dict["copypaste"].reset_session()
        except AttributeError:
            # For proxy session factories, they just create a new session next time they are called
            pass

        def local_process_site(site_name, ip_address, write_content, display):
            success = self.process_site_for_ip(site_name, clients_dict[site_name], ip_address, write_content, display)
            if success:
                self.ip_skips = 0 # reset on success
            elif display_manager:
                display_manager.update(site_name, "❌ Failed", "❌")

        if sequential:
            local_process_site("ssavr", ip_address, w_ssavr, display_manager)
            local_process_site("copypaste", ip_address, w_cp, display_manager)
        else:
            import threading
            thread_ssavr = threading.Thread(
                target=local_process_site, 
                args=("ssavr", ip_address, w_ssavr, display_manager)
            )
            thread_cp = threading.Thread(
                target=local_process_site, 
                args=("copypaste", ip_address, w_cp, display_manager)
            )
            
            thread_ssavr.start()
            thread_cp.start()
            thread_ssavr.join()
            thread_cp.join()

    def _proxy_worker(self, w_ssavr, w_cp, proxy_manager_display):
        """Worker thread that continuously pulls proxies and processes the sites."""
        while self.running:
            proxy = self.proxy_manager.get_next_proxy()
            if not proxy:
                time.sleep(5)
                continue
                
            proxy_reqs = self.proxy_manager.get_requests_dict(proxy)
            proxy_addr = proxy['address']
            
            # Bug fix #4: capture proxy_reqs by default arg to avoid late-binding closure bug
            def proxy_session_factory(reqs=proxy_reqs):
                session = requests.Session()
                session.proxies.update(reqs)
                session.timeout = config.PROXY_CONNECT_TIMEOUT
                return session

            proxy_clients = {
                "ssavr": SsavrClient(proxy_session_factory),
                "copypaste": CopyPasteClient(proxy_session_factory)
            }
            
            try:
                # Use a specific adapter for this proxy
                proxy_adapter = ProxyDisplayAdapter(proxy_manager_display, proxy_addr)
                
                display_ip = f"PROXY | {proxy_addr}"
                
                self.process_ip_with_clients(display_ip, proxy_clients, w_ssavr, w_cp, proxy_adapter, sequential=True)
                
                self.stats["ssavr"]["proxy_success"] += 1
                self.stats["copypaste"]["proxy_success"] += 1
                
            except requests.exceptions.RequestException:
                self.proxy_manager.mark_failure(proxy_addr)
            except Exception:
                self.proxy_manager.mark_failure(proxy_addr)
                
            time.sleep(0.1)  # Minimal delay for maximum throughput


    def run(self):
        # Handle History commands
        if self.args.show_history:
            print("\n=== MESSAGE HISTORY ===")
            if self.storage.history["messages"]:
                for i, msg in enumerate(self.storage.history["messages"], 1):
                    print(f"{i}. {msg}")
            else:
                print("No messages in history.")
            return

        if self.args.add_history:
            self.storage.add_to_history(self.args.add_history)
            print(f"✓ Message added to history: {self.args.add_history}")
            return
            
        if self.args.remove_history:
            if self.storage.remove_from_history(self.args.remove_history):
                print(f"✓ Message removed from history")
            else:
                print(f"✗ Message not found in history")
            return

        # Save writes to history
        if self.args.write: self.storage.add_to_history(self.args.write)
        if self.args.target_ssavr: self.storage.add_to_history(self.args.target_ssavr)
        if self.args.target_copypaste: self.storage.add_to_history(self.args.target_copypaste)

        w_ssavr, w_cp = self.get_write_contents()
        loop_iteration = 0
        import threading
        
        split_display = SplitScreenDisplay()
        tor_adapter = TorDisplayAdapter(split_display)
        
        # Connect Tor first to ensure the main script doesn't block
        self.print_startup_info()
        if not self.tor.connect():
            sys.exit(1)

        # Start Proxy Fetching and Workers IF NOT targeting single Tor IP
        if not self.args.single:
            print("\n🚀 Starting Proxy Engine...")
            self.proxy_manager.fetch_proxies(randomize=self.args.randomize)
            
            split_display.proxy_total = len(self.proxy_manager.proxies)
            
            self.proxy_executor = ThreadPoolExecutor(max_workers=config.PROXY_THREAD_COUNT)
            for _ in range(config.PROXY_THREAD_COUNT):
                self.proxy_executor.submit(self._proxy_worker, w_ssavr, w_cp, split_display)
        
        split_display.start()

        try:
            while self.running:
                if self.args.loop:
                    loop_iteration += 1
                    print(f"\n{'='*80}")
                    print(f"🔄 ROUND #{loop_iteration}")
                    print(f"{'='*80}\n")
                
                exit_nodes = self.tor.get_exit_nodes()
                exit_nodes_items = list(exit_nodes.items())
                
                if self.args.randomize:
                    random.shuffle(exit_nodes_items)
                
                total = len(exit_nodes_items)
                start_index = (self.args.index - 1) if self.args.index and self.args.index > 0 else 0
                
                items_to_scan = []
                if self.args.single:
                    if self.args.single < 1 or self.args.single > total:
                         print(f"✗ Error: IP index {self.args.single} out of range (1-{total})")
                         return
                    idx = self.args.single - 1
                    items_to_scan = [(idx + 1, exit_nodes_items[idx])]
                else:
                    items_to_scan = enumerate(exit_nodes_items[start_index:], start=start_index + 1)

                consecutive_failures = 0  # Track consecutive IP verification failures
                
                items_list = list(items_to_scan)
                idx = 0
                retrying_current = False
                
                while idx < len(items_list) and self.running:
                    i, (fingerprint, ip_address) = items_list[idx]
                    
                    # Start Display for this IP
                    split_display.start_tor_ip(i, total, ip_address, loop_iteration if self.args.loop else None)
                    split_display.refresh()
                    
                    verified = self.tor.change_exit_node(fingerprint, ip_address, verbose=False)

                    if verified:
                        retrying_current = False
                        
                        self.process_ip_with_clients(ip_address, self.clients, w_ssavr, w_cp, tor_adapter)
                        
                        # Move to next IP
                        idx += 1
                        
                    else:
                        # FAILURE HANDLING
                        if not retrying_current:
                            # FIRST FAILURE: Reset Circuit & Retry SAME IP
                            tor_adapter.log(f"❌ Verification failed. Hard resetting Tor and retrying same IP...")
                            self.tor.reset_circuit()
                            retrying_current = True
                            # Do NOT increment idx, loop will repeat same IP
                        else:
                            # SECOND FAILURE (After Reset): Skip this IP
                            tor_adapter.log(f"❌ Failed again after reset. Skipping IP {ip_address}.")
                            self.ip_skips += 1
                            retrying_current = False
                            idx += 1 # Move to next IP
                    
                    if self.args.single: break

                if not self.args.loop:
                    break
                    
                print(f"\n{'='*80}")
                print(f"✅ Round #{loop_iteration} completed. Restarting in 5 seconds...")
                print(f"{'='*80}\n")
                time.sleep(5)
                
        except KeyboardInterrupt:
            self.handle_interrupt(None, None)
        finally:
            if 'split_display' in locals():
                split_display.stop()
            self.running = False # Stop proxy threads
            if self.proxy_executor:
                self.proxy_executor.shutdown(wait=False, cancel_futures=True)
            # Tor shutdown handled by atexit handler in TorManager


# Helper to load file content
def load_file_content(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except Exception as e:
        print(f"✗ Error reading file {filepath}: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=f'Tor Clipboard Scanner v{config.VERSION} (Refactored)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Args from original
    parser.add_argument('--socks-port', type=int, help='Tor SOCKS port')
    parser.add_argument('--control-port', type=int, help='Tor control port')
    
    parser.add_argument('-w', '--write', help='Write message to both sites')
    parser.add_argument('-wf', '--write-file', help='Write message from file to both sites')
    
    parser.add_argument('-t', '--target', choices=['SS', 'CP'], help='Target: SS (ssavr) or CP (copypaste)')
    parser.add_argument('-ts', '--target-ssavr', help='Write message only to ssavr.com')
    parser.add_argument('-tsf', '--target-ssavr-file', help='Write from file only to ssavr.com')
    parser.add_argument('-tc', '--target-copypaste', help='Write message only to copy-paste.online')
    parser.add_argument('-tcf', '--target-copypaste-file', help='Write from file only to copy-paste.online')
    
    parser.add_argument('-o', '--overwrite', action='store_true', help='Overwrite own messages')
    parser.add_argument('-a', '--all', action='store_true', help='Overwrite ANY content (⚠️ dangerous!)')
    
    parser.add_argument('-i', '--index', type=int, help='Start from IP number (1-based)')
    parser.add_argument('-s', '--single', type=int, help='Scan ONLY one IP (1-based)')
    parser.add_argument('-l', '--loop', action='store_true', help='Loop mode (monitor changes)')
    parser.add_argument('-b', '--randomize', action='store_true', help='Randomize IP order')
    
    parser.add_argument('-x', '--add-history', help='Add message to history')
    parser.add_argument('-k', '--show-history', action='store_true', help='Show message history')
    parser.add_argument('-r', '--remove-history', help='Remove message from history')
    parser.add_argument('-u', '--update', action='store_true', help='Check for updates')
    parser.add_argument('--clean-data', action='store_true', help='Remove all generated data (logs, cache, scanner tor)')
    parser.add_argument('--uninstall', action='store_true', help='Clean up and show uninstall instructions')

    args = parser.parse_args()

    # Check for updates first
    if args.update:
        updater.check_for_updates()
        return

    # Clean data / Uninstall
    if args.clean_data or args.uninstall:
        import shutil
        print("🧹 Cleaning generated data...")
        
        # Remove data folder contents
        if config.DATA_DIR.exists():
            for item in config.DATA_DIR.iterdir():
                if item.is_dir():
                    shutil.rmtree(item)
                    print(f"   ✓ Removed {item.name}/")
                else:
                    item.unlink()
                    print(f"   ✓ Removed {item.name}")
        
        # Remove log files in root
        for f in ["changes.txt", "ssavr_clean.txt", "copypaste_clean.txt"]:
            p = config.BASE_DIR / f
            if p.exists():
                p.unlink()
                print(f"   ✓ Removed {f}")
        
        print("\n✓ All generated data removed!")
        
        if args.uninstall:
            print("\n📦 To complete uninstall, remove the project folder:")
            print(f"   rm -rf {config.BASE_DIR}")
        return

    # Constraints checks
    if args.single and args.index: parser.error("-s/--single cannot be used with -i/--index")
    if args.single and args.loop: parser.error("-s/--single cannot be used with -l/--loop")
    if args.single and args.randomize: parser.error("-s/--single cannot be used with -b/--randomize")
    # Loop + Write constraint removed
    if args.all and args.overwrite: parser.error("-a/--all cannot be used with -o/--overwrite")
    
    # Load files
    if args.write_file: args.write = load_file_content(args.write_file)
    if args.target_ssavr_file: args.target_ssavr = load_file_content(args.target_ssavr_file)
    if args.target_copypaste_file: args.target_copypaste = load_file_content(args.target_copypaste_file)

    app = ScannerApp(args)
    app.run()

if __name__ == "__main__":
    main()
