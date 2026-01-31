import json
import logging
from pathlib import Path
from datetime import datetime
from . import config, utils

class StorageManager:
    def __init__(self):
        self.history = self._load_history()
        self.current_state = self._load_current_state()
        self.clean_cache = {"ssavr": {}, "copypaste": {}}
        self._load_clean_cache()

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

    def _load_clean_cache(self):
        self._load_cache_file(config.SSAVR_CLEAN, "ssavr")
        self._load_cache_file(config.COPYPASTE_CLEAN, "copypaste")
        print(f"📋 Loaded clean cache: {len(self.clean_cache['ssavr'])} ssavr, {len(self.clean_cache['copypaste'])} copypaste")

    def _load_cache_file(self, filepath, key):
        if Path(filepath).exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    current_ip = None
                    for line in f:
                        if line.startswith('['):
                            ip = utils.extract_ip_from_text(line)
                            if ip:
                                current_ip = ip
                        elif current_ip and line.strip() and not line.startswith('-'):
                            self.clean_cache[key][current_ip] = line.strip()
                            current_ip = None
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
        """
        Updates the human-readable 'current_*.txt' files.
        Re-implements logic to preserve multi-line content for other IPs.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = config.CURRENT_SSAVR if "ssavr" in site_name else config.CURRENT_COPYPASTE
        
        current_data = {}
        
        # Parse existing
        if filename.exists():
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    current_ip = None
                    reading_content = False
                    content_lines = []
                    
                    for line in f:
                        if line.startswith("[IP:"):
                            if current_ip and reading_content:
                                current_data[current_ip]["content"] = '\n'.join(content_lines).strip()
                                reading_content = False
                                content_lines = []
                            
                            current_ip = utils.extract_ip_from_text(line)
                            if current_ip and current_ip not in current_data:
                                current_data[current_ip] = {"timestamp": "", "content": ""}
                        
                        elif current_ip and "Last updated:" in line:
                            ts = line.split("Last updated:")[1].strip()
                            current_data[current_ip]["timestamp"] = ts
                        
                        elif current_ip and line.strip().startswith("Content:"):
                            cont = line.split("Content:", 1)[1].strip()
                            content_lines = [cont] if cont else []
                            reading_content = True
                        
                        elif current_ip and reading_content and not line.startswith("-"):
                            if line.strip():
                                content_lines.append(line.rstrip())
                        
                        elif line.startswith("-"):
                            if current_ip and reading_content:
                                current_data[current_ip]["content"] = '\n'.join(content_lines).strip()
                                reading_content = False
                                content_lines = []
                    
                    if current_ip and reading_content:
                        current_data[current_ip]["content"] = '\n'.join(content_lines).strip()

            except Exception as e:
                utils.debug_log(f"Error reading view file {filename}: {e}")

        # Update target IP
        current_data[ip_address] = {
            "timestamp": timestamp,
            "content": content if content else "(empty)"
        }

        # Write back
        try:
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
        except Exception as e:
            utils.debug_log(f"Error writing view file {filename}: {e}")

