# 🌐 Paste Scanner Suite

**v8.5.0** - Unified Anonymous Clipboard Monitoring & Brute-Forcing.

Includes two powerful modules:
1. **Tor IP Rotation Tool** (`--mod1`): Scans ssavr.com, copy-paste.online, airforshare.com via dedicated Tor exit nodes.
2. **HTTP Proxy Brute-Forcer** (`--mod2`): Sequentially brute-forces URLs on cl1p.net, justpaste.it, and rentry.co using 12,000+ free proxies with parallel scanning (up to 2500 workers).

## ✨ Features

- **Blazing Fast**: Uses C-compiled extensions (`fast_utils.c`) to bypass Python's GIL. Runs regex & language detection thousands of times faster.
- **Token Rotation**: Supports multiple cl1p.net API keys loaded from `data/cl1p_keys.txt`, distributed across workers for maximum throughput.
- **Smart Dedup & V2 Tracking**: Deduplicates by content hash and tracks message revisions (V2, V3, ...) when the same URL changes over time.
- **Concurrent Proxy Engine**: Dynamically fetches proxies from 25+ sources (~12,000+ proxies), auto-refreshes every 30 minutes.
- **Optional Content Filter**: Use `-f` to skip non-Latin script content (Arabic, Chinese, Russian, etc.).
- **Zero Config**: Automatic Tor instances and automated GCC dependency compiling for the C extensions.

## 🚀 Quick Start (Automated Install)

Simply run the app. If the C-extensions haven't been compiled yet, it will automatically detect it and compile them on the fly.

```bash
# 1. Download the code
git clone https://github.com/Jester-tek/ssavr-copypaste-scanner.git
cd ssavr-copypaste-scanner

# 2. Run the automated installer for Python dependencies & Tor
chmod +x setup.sh
./setup.sh

# 3. Start the scanner
source venv/bin/activate
python3 main.py
```

*Note: If you run `main.py` directly without `setup.sh`, ensure `gcc` and `python3-pip` are already installed.*

## 🔑 cl1p.net API Keys (Optional but recommended)

cl1p.net works without an API key, but **messages written without a key are destroyed after the first read** (burn-after-reading). To make messages persist for up to 1 month, you need an API key.

1. Create a free account at [cl1p.net](https://cl1p.net) and set default message duration to **1 month**.
2. Copy your API token from your dashboard.
3. Add it to `data/cl1p_keys.txt` (one key per line):

```
# data/cl1p_keys.txt — one API key per line, lines starting with # are comments
myFirstToken123
mySecondToken456
```

The scanner will automatically rotate across all keys for maximum speed. The `data/` folder is gitignored — your keys stay private.

## 📖 Usage

**You MUST supply a mandatory flag to select the tool:**

### Tool 1: Tor Scanner (`--mod1`)

```bash
# Basic
python3 main.py --mod1                  # Read-only loop across all Tor sites
python3 main.py --mod1 -s 139           # Scan only Tor IP #139
python3 main.py --mod1 -l               # Loop mode

# Writing
python3 main.py --mod1 -wf msg.txt      # Write from file
python3 main.py --mod1 -tsf msgSS.txt -tcf msgCP.txt # Different files per site
```

### Tool 2: Proxy Brute-Forcer (`--mod2`)

```bash
# Basic read-only
python3 main.py --mod2 -t cl1p          # Scan cl1p.net (500 workers)
python3 main.py --mod2 -t rentry        # Scan rentry.co (2500 workers)
python3 main.py --mod2 -t all           # Scan cl1p, rentry, justpaste simultaneously

# Writing (cl1p only — rentry/justpaste are read-only)
python3 main.py --mod2 -t cl1p -wf msg.txt           # Write from file
python3 main.py --mod2 -t all -wf msg.txt             # Scan all, write to cl1p

# Content filter (optional)
python3 main.py --mod2 -t all -f        # Skip non-Latin content (Arabic/Chinese/etc)

# Advanced
python3 main.py --mod2 -t cl1p --start abc  # Resume from a specific URL
python3 main.py --mod2 -t all --reset-all   # ⚠️ CAUTION: Deletes all states/dedup hashes
```

### Key flags for `--mod2`

| Flag | Description |
|------|-------------|
| `-t` | Target site: `cl1p`, `rentry`, `justpaste`, or `all` |
| `-wf FILE` | Write message from file (cl1p only) |
| `-w TEXT` | Write message inline (cl1p only) |
| `-f` / `--filter` | Enable foreign language filter (skips content >50% non-Latin script) |
| `--start URL` | Start scanning from a specific URL (e.g., `--start abc`) |
| `--reset` | Reset scan position for the selected target |
| `--reset-all` | Reset scan positions for all targets |

## 📁 Files Generated

```
📂 ssavr-copypaste-scanner/
├── cl1p_clean.txt           # Proxy module output
├── rentry_clean.txt
├── justpaste_clean.txt
├── ssavr_clean.txt          # Tor module output
├── copypaste_clean.txt
├── airforshare_clean.txt
└── 📂 data/                 # Auto-maintained states and history (gitignored)
    └── cl1p_keys.txt        # Your cl1p API keys (one per line)
```

## 🗑️ Uninstall

```bash
python3 main.py --mod1 --uninstall
rm -rf ssavr-copypaste-scanner
```

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md)
