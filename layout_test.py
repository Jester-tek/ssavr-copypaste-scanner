import time
import sys
from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
import threading
from collections import deque

console = Console()
h = console.size.height - 4
tor_lines = deque(maxlen=h)
proxy_lines = deque(maxlen=h)

for i in range(h):
    tor_lines.append(f"Tor log {i}")
    proxy_lines.append(f"Proxy log {i}")

layout = Layout()
layout.split_row(
    Layout(name="tor", ratio=1),
    Layout(name="proxy", ratio=1)
)

tor_text = Text("\n".join(tor_lines))
proxy_text = Text("\n".join(proxy_lines))

layout["tor"].update(Panel(tor_text, title="TOR", border_style="blue"))
layout["proxy"].update(Panel(proxy_text, title="PROXIES", border_style="yellow"))

with Live(layout, screen=True, console=console, refresh_per_second=4) as live:
    for i in range(10):
        tor_lines.append(f"New Tor log {i}")
        proxy_lines.append(f"New Proxy log {i}")
        tor_text = Text("\n".join(tor_lines))
        proxy_text = Text("\n".join(proxy_lines))
        layout["tor"].update(Panel(tor_text, title="TOR", border_style="blue"))
        layout["proxy"].update(Panel(proxy_text, title="PROXIES", border_style="yellow"))
        live.update(layout)
        time.sleep(0.5)
