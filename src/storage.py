import ctypes
from pathlib import Path
import hashlib

try:
    _fast = ctypes.CDLL(str(Path(__file__).parent / "fast_utils.so"))
    _fast.fast_hash_content.argtypes = [ctypes.c_char_p]
    _fast.fast_hash_content.restype = ctypes.c_uint64
    _ext_loaded = True
except Exception:
    _ext_loaded = False

import json
import logging
from datetime import datetime
import time
import threading
from . import config, utils

class StorageManager:
    def __init__(self):
        self.history = self._load_history()
        self.current_state = self._load_current_state()
        self.clean_cache = {"ssavr": {}, "copypaste": {}, "airforshare": {}}
        self.clean_hashes = {"ssavr": set(), "copypaste": set(), "airforshare": set()}
        self._load_clean_cache()
        
        # UI/File I/O optimizations
        self.view_files_cache = {"ssavr": {}, "airforshare": {}, "copypaste": {}}
        self.last_view_flush = time.time()
        self.view_lock = threading.Lock()

    def _load_history(self):
        if config.HISTORY_FILE.exists():
            try:
                with open(config.HISTORY_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                utils.debug_log(f"Error loading history: {e}")
        return {"messages": []}

    def save_history(self):
        with open(config.HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.history, f, indent=2, ensure_ascii=False)

    def add_to_history(self, message):
        clean_msg = utils.clean_text(message)
        if clean_msg not in self.history["messages"]:
            self.history["messages"].append(clean_msg)
            self.save_history()

    def remove_from_history(self, message):
        clean_msg = utils.clean_text(message)
        if clean_msg in self.history["messages"]:
            self.history["messages"].remove(clean_msg)
            self.save_history()
            return True
        return False

    def _load_current_state(self):
        if config.CURRENT_STATE_FILE.exists():
            try:
                with open(config.CURRENT_STATE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def save_current_state(self):
        with open(config.CURRENT_STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.current_state, f, indent=2, ensure_ascii=False)

    def _fast_hash(self, content):
        if _ext_loaded:
            return _fast.fast_hash_content(content.encode("utf-8", errors="ignore"))
        h = hashlib.sha256(content.strip().lower().encode("utf-8")).hexdigest()
        return h

    def is_global_duplicate(self, site_key, content):
        return self._fast_hash(content) in self.clean_hashes[site_key]

    def add_global_hash(self, site_key, content):
        self.clean_hashes[site_key].add(self._fast_hash(content))

    def _load_clean_cache(self):
        self._load_cache_file(config.SSAVR_CLEAN, "ssavr")
        self._load_cache_file(config.COPYPASTE_CLEAN, "copypaste")
        self._load_cache_file(config.AIRFORSHARE_CLEAN, "airforshare")
        print(f"📋 Loaded clean cache: {len(self.clean_cache['ssavr'])} ssavr, {len(self.clean_cache['copypaste'])} copypaste, {len(self.clean_cache['airforshare'])} airforshare")

    def _load_cache_file(self, filepath, key):
        if Path(filepath).exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    current_ip = None
                    content_block = []
                    for line in f:
                        if line.startswith('['):
                            # Salva blocco precedente
                            if current_ip and content_block:
                                full_content = '\n'.join(content_block)
                                self.clean_cache[key][current_ip] = full_content
                                self.clean_hashes[key].add(self._fast_hash(full_content))
                            ip = utils.extract_ip_from_text(line)
                            if ip:
                                current_ip = ip
                                content_block = []
                        elif current_ip and not line.startswith('-'*80) and not line.startswith('-'*70):
                            if line.strip() != "":
                                content_block.append(line.strip())
                    
                    # Salva ultimo blocco
                    if current_ip and content_block:
                        full_content = '\n'.join(content_block)
                        self.clean_cache[key][current_ip] = full_content
                        self.clean_hashes[key].add(self._fast_hash(full_content))
                        
            except Exception as e:
                utils.debug_log(f"Error loading {key} clean cache: {e}")

    def log_to_file(self, filename, content, append=True):
        mode = 'a' if append else 'w'
        path = Path(filename)
        # Ensure parent (data dir mostly) exists, though config ensures data/ exists
        path.parent.mkdir(exist_ok=True, parents=True)
        with open(path, mode, encoding='utf-8') as f:
            f.write(content + '\n')
    def update_current_view_file(self, site_name, ip_address, content):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if "ssavr" in site_name:
            key = "ssavr"
        elif "airforshare" in site_name:
            key = "airforshare"
        else:
            key = "copypaste"
            
        with self.view_lock:
            display_content = content if content else "(empty)"
            self.view_files_cache[key][ip_address] = {
                "timestamp": timestamp,
                "content": display_content
            }
            now = time.time()
            if now - self.last_view_flush > 5:
                self.last_view_flush = now
                threading.Thread(target=self._flush_view_files_safe, daemon=True).start()

    def _flush_view_files_safe(self):
        with self.view_lock:
            snapshot = {k: dict(v) for k, v in self.view_files_cache.items()}
            
        for key, filename in [("ssavr", config.CURRENT_SSAVR), ("airforshare", config.CURRENT_AIRFORSHARE), ("copypaste", config.CURRENT_COPYPASTE)]:
            if not snapshot[key]: continue
            try:
                if len(self.view_files_cache[key]) > 20000: pass
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"# Current state of {key}\n")
                    f.write(f"# Last updated: {timestamp}\n")
                    f.write(f"# Total IPs tracked: {len(snapshot[key])}\n")
                    f.write("="*80 + "\n\n")
                    for ip in sorted(snapshot[key].keys()):
                        data = snapshot[key][ip]
                        f.write(f"[IP: {ip}]\n")
                        f.write(f"  Last updated: {data['timestamp']}\n")
                        f.write(f"  Content: {data['content']}\n")
                        f.write("-" * 80 + "\n")
            except Exception as e:
                utils.debug_log(f"Error flushing view file {filename}: {e}")
