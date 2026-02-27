from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich import box
import threading
from collections import deque

class SplitScreenDisplay:
    """Split-screen terminal display: Tor on the left, Proxies on the right."""

    def __init__(self):
        self.console = Console()
        # Dynamically adjust to terminal size (approx 6 lines for headers/borders)
        h = max(20, self.console.height - 6)
        self.tor_lines = deque(maxlen=h)
        self.proxy_lines = deque(maxlen=h)
        self.proxy_count = 0
        self.proxy_total = 0
        self.lock = threading.Lock()
        self.live = None

    # ── Tor column ──────────────────────────────────────────────

    def start_tor_ip(self, index, total, ip_address, loop_count=None):
        """Add an IP header to the Tor column."""
        loop_info = f" [Round #{loop_count}]" if loop_count else ""
        header = f"[bold cyan]🌐 IP {index}/{total}{loop_info} | {ip_address}[/bold cyan]"
        with self.lock:
            if self.tor_lines:
                self.tor_lines.append("")
            self.tor_lines.append(header)

    def log_tor(self, text):
        """Append a line to the Tor column."""
        with self.lock:
            self.tor_lines.append(f"  {text}")

    # ── Proxy column ────────────────────────────────────────────

    def start_proxy_ip(self, proxy_addr):
        """Add a proxy header line to the Proxy column and return its number."""
        with self.lock:
            self.proxy_count += 1
            n = self.proxy_count
            total = self.proxy_total or "?"
            return n, total

    def log_proxy(self, proxy_addr, n, total, text):
        """Append a line to the Proxy column."""
        with self.lock:
            self.proxy_lines.append(f"[bold yellow]PROXY [{n}/{total}] | {proxy_addr}[/bold yellow]")
            self.proxy_lines.append(f"  {text}")
            self.proxy_lines.append("") # visual breathing room

    # ── Rendering ───────────────────────────────────────────────

    def _render_unlocked(self):
        """Build layout WITHOUT acquiring lock (caller must hold lock)."""
        tor_text = Text.from_markup("\n".join(self.tor_lines)) if self.tor_lines else Text("Waiting for Tor…", style="dim")
        proxy_text = Text.from_markup("\n".join(self.proxy_lines)) if self.proxy_lines else Text("Waiting for proxies…", style="dim")
        layout = Layout()
        layout.split_row(
            Layout(name="tor", ratio=1),
            Layout(name="proxy", ratio=1),
        )
        layout["tor"].update(Panel(tor_text, title="[bold blue]TOR[/bold blue]", border_style="blue", box=box.ROUNDED, expand=True))
        layout["proxy"].update(Panel(proxy_text, title="[bold yellow]PROXIES[/bold yellow]", border_style="yellow", box=box.ROUNDED, expand=True))
        return layout

    def _render(self):
        """Build the two-column layout (acquires lock)."""
        with self.lock:
            return self._render_unlocked()

    def start(self):
        """Start the Live display (screen=True takes over the full terminal)."""
        self.live = Live(self._render(), refresh_per_second=1, console=self.console, screen=True)
        self.live.start()
        # Background refresh ticker — updates the display every 250ms without holding our lock
        self._refresh_running = True
        self._refresh_thread = threading.Thread(target=self._auto_refresh, daemon=True)
        self._refresh_thread.start()

    def _auto_refresh(self):
        """Background thread: re-renders the layout at ~4fps without needing an explicit refresh() call."""
        import time
        while self._refresh_running and self.live:
            try:
                with self.lock:
                    rendered = self._render_unlocked()
                self.live.update(rendered)
            except Exception:
                pass
            time.sleep(0.05)

    def refresh(self):
        """Manual refresh hint — no-op since _auto_refresh handles it."""
        pass

    def stop(self):
        """Stop the Live display and background refresh thread."""
        self._refresh_running = False
        if self.live:
            self.live.stop()
            self.live = None


class TorDisplayAdapter:
    """Adapter passed to process_site_for_ip when called from the Tor loop."""
    def __init__(self, split_display):
        self.split = split_display

    def update(self, site, message, icon=None):
        prefix = icon or "•"
        self.split.log_tor(f"  {prefix} [bold]{site}:[/bold] {message}")
        # no refresh needed — _auto_refresh handles it

    def log(self, text):
        self.split.log_tor(text)
        self.split.refresh()

    def context(self):
        class Dummy:
            def __enter__(self): pass
            def __exit__(self, *a): pass
        return Dummy()


class ProxyDisplayAdapter:
    """Adapter passed to process_site_for_ip when called from proxy threads."""
    def __init__(self, split_display, proxy_addr):
        self.split = split_display
        self.proxy_addr = proxy_addr
        self.n, self.total = split_display.start_proxy_ip(proxy_addr)

    def update(self, site, message, icon=None):
        prefix = icon or "•"
        self.split.log_proxy(self.proxy_addr, self.n, self.total, f"{prefix} [bold]{site}:[/bold] {message}")

    def log(self, text):
        self.split.log_proxy(self.proxy_addr, self.n, self.total, text)
        self.split.refresh()

    def context(self):
        class Dummy:
            def __enter__(self): pass
            def __exit__(self, *a): pass
        return Dummy()
