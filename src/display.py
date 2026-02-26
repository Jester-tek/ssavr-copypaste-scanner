from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich import box
import threading

class ScanDisplay:
    def __init__(self):
        self.console = Console()
        self.status = {
            "ssavr": {"stage": "pending", "message": "Pending...", "icon": "⏳"},
            "copypaste": {"stage": "pending", "message": "Pending...", "icon": "⏳"}
        }
        self.ip_info = ""
        self.live = None
        self.lock = threading.Lock()

    def start_ip(self, index, total, ip_address, loop_count=None):
        loop_info = f" [Round #{loop_count}]" if loop_count else ""
        self.ip_info = f"🌐 IP {index}/{total}{loop_info} | {ip_address}"
        self.status = {
            "ssavr": {"stage": "loading", "message": "Reading...", "icon": "📖"},
            "copypaste": {"stage": "loading", "message": "Reading...", "icon": "📖"}
        }
        # Print the header (rule)
        self.console.print() 
        self.console.rule(style="blue")
        self.console.print(f"[bold cyan]{self.ip_info}[/bold cyan]", justify="center")
        self.console.rule(style="blue")

    def create_table(self):
        # Create a new table for render (uses full width automatically!)
        table = Table(box=box.SIMPLE, show_header=False, show_edge=False, padding=0, expand=True)
        table.add_column("Site", style="bold white", width=20)
        table.add_column("Status", ratio=1)
        
        # SSAVR Row
        s_stats = self.status["ssavr"]
        table.add_row(
            "ssavr.com", 
            f"{s_stats['icon']} {s_stats['message']}"
        )
        
        # CopyPaste Row
        c_stats = self.status["copypaste"]
        table.add_row(
            "copy-paste.online", 
            f"{c_stats['icon']} {c_stats['message']}"
        )
        return table

    def log(self, w_text):
        """Log a message persistently above/below the table."""
        with self.lock:
             self.console.print(w_text)

    def update(self, site, message, icon=None):
        with self.lock:
            self.status[site]["message"] = message
            if icon:
                self.status[site]["icon"] = icon
            
            # Trigger refresh if live is active
            if self.live:
                self.live.update(self.create_table())

    def context(self):
        # We manually manage the Live object so we can update it from threads
        self.live = Live(self.create_table(), refresh_per_second=4, transient=False, console=self.console)
        return self.live


class ProxyDisplayManager:
    """A quiet display manager for background proxy threads.
    It suppresses table updates to prevent UI tearing, but allows persistent logging.
    Now includes a global proxy counter.
    """
    def __init__(self, console, proxy_total=0):
        self.console = console
        self.lock = threading.Lock()
        self.proxy_total = proxy_total
        self.proxy_count = 0

    def get_and_increment_counter(self):
        with self.lock:
            self.proxy_count += 1
            n = self.proxy_count
            total = self.proxy_total or "?"
            return n, total

    def update(self, site, message, icon=None):
        pass # Ignore table updates

    def log(self, w_text):
        """Standard log, useful if we just want to output something.
           Use `log_proxy_result` to automatically prepend the proxy IP and counter.
        """
        with self.lock:
            self.console.print(w_text)
            
    def log_proxy_result(self, proxy_addr, n, total, text):
        """Formats the proxy output consistently, matching the old style but cleaner."""
        prefix = f"[bold yellow]PROXY [{n}/{total}] | {proxy_addr}[/bold yellow]"
        with self.lock:
            self.console.print(f"   {prefix}  {text}")

    def context(self):
        class DummyContext:
            def __enter__(self): pass
            def __exit__(self, *args): pass
        return DummyContext()
