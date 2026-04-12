# 🌐 Paste Scanner Suite

**v7.0.0** - Unified Anonymous Clipboard Monitoring & Brute-Forcing.

Includes two powerful modules:
1. **Tor IP Rotation Tool** (`--mod1`): Scans ssavr.com, copy-paste.online, airforshare.com via dedicated Tor exit nodes.
2. **HTTP Proxy Brute-Forcer** (`--mod2`): Squentially brute-forces URLs on cl1p.net, justpaste.it, and rentry.co using 16,000+ free proxies with parallel scanning (up to 200 workers).

## ✨ Features

- **Blazing Fast Analytics**: Uses C-compiled extensions (`fast_utils.c`) to bypass Python's GIL. Runs regex & language detection thousands of times faster.
- **Smart Dedup & V2 Tracking**: The Proxy Brute-Forcer saves everything in RAM, deduplicates natively, and tracks message revisions on the same URL (e.g., marks as V2, V3 if the text changes over time).
- **Concurrent Proxy Engine**: Dynamically fetches proxies from 13 sources.
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
# Basic
python3 main.py --mod2 -t cl1p          # Fast scan cl1p.net
python3 main.py --mod2 -t all           # Scan cl1p, rentry, justpaste simultaneously!

# Writing (cl1p only)
python3 main.py --mod2 -t cl1p -wf msg.txt           # Write from file
python3 main.py --mod2 -t all -tcf msgCL1P.txt       # Scan all, but write only to cl1p

# Advanced
python3 main.py --mod2 -t all --reset-all # ⚠️ CAUTION: Deletes all states/dedup hashes
```

## 📁 Files Generated

```
📂 ssavr-copypaste-scanner/
├── cl1p_clean.txt           # Proxy module output
├── rentry_clean.txt
├── justpaste_clean.txt
├── ssavr_clean.txt          # Tor module output
├── copypaste_clean.txt
├── airforshare_clean.txt
└── 📂 data/                 # Auto-maintained states and history
```

## 🗑️ Uninstall

```bash
python3 main.py --mod1 --uninstall
rm -rf ssavr-copypaste-scanner
```

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md)
