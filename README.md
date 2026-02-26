everything written here is completely done by AI, even the readme.

# 🌐 Tor & Proxy Clipboard Scanner

**v6.0.0** - Anonymous clipboard monitoring through Tor exit nodes and 16,000+ free proxies with parallel scanning.

Scan ssavr.com and copy-paste.online through Tor and a massive pool of dynamic proxies for maximum anonymity and speed.

## ✨ Features

- **Concurrent Proxy Engine**: Dynamically fetches 16,000+ free proxies from 13 sources, running 100 simultaneous threads!
- **Split-Screen UI**: Beautiful dual-column terminal layout (Tor on left, Proxies on right).
- **Zero Config**: Automatic dedicated Tor instance (no system Tor modification).
- **Loop Mode**: Continuous monitoring with intelligent change detection and auto-recovery.
- **Safe Isolation**: Scanner's Tor never affects other Tor apps (Simplex, etc.).

## 🚀 Quick Start (Automated Install)

We provide a seamless setup script that installs Tor and sets up a Python virtual environment automatically:

```bash
# 1. Download the code
git clone https://github.com/your-repo/ssavr-copypaste-scanner.git
cd ssavr-copypaste-scanner

# 2. Run the automated installer
chmod +x setup.sh
./setup.sh

# 3. Start the scanner
source venv/bin/activate
python3 main.py
```

**That's it!** The scanner starts its own Tor instance automatically on port 9060. Your system Tor (port 9050) is never touched.

## 📖 Usage

```bash
# Basic
python3 main.py                         # Read-only scan
python3 main.py -s 139                  # Scan only IP #139
python3 main.py -l                      # Loop mode (monitor changes)

# Writing
python3 main.py -w "Hello"              # Write to both sites
python3 main.py -wf msg.txt             # Write from file
python3 main.py -ts "Hi SS" -tc "Hi CP" # Different per site
python3 main.py -l -w "Hi"              # Loop + Write combined

# Advanced
python3 main.py -w "Test" -o            # Overwrite own messages
python3 main.py -w "Test" -a            # Overwrite EVERYTHING (⚠️)
python3 main.py -i 100                  # Start from IP #100
python3 main.py -b                      # Randomize order
python3 main.py -u                      # Check for updates

# Maintenance
python3 main.py --clean-data            # Remove all generated data
python3 main.py --uninstall             # Clean + show uninstall steps
```

## 📁 Files

All data stays inside the project folder:

```
📂 ssavr-copypaste-scanner/
├── ssavr_clean.txt          # New content (no duplicates)
├── copypaste_clean.txt      # New content (no duplicates)
├── changes.txt              # Changes detected in any mode
└── 📂 data/
    ├── scanner_tor/         # Dedicated Tor instance data
    ├── ssavr_detailed.txt   # All reads
    ├── copypaste_detailed.txt
    ├── current_*.txt        # Current state per IP
    ├── inputs_history.json  # Your message history
    └── debug.log
```

## 🔧 Options

| Option | Description |
|--------|-------------|
| `-w TEXT` | Write to both sites |
| `-wf FILE` | Write from file |
| `-ts/-tc` | Write to specific site |
| `-o` | Overwrite own messages |
| `-a` | Overwrite ANY content (⚠️) |
| `-s NUM` | Scan only one IP |
| `-i NUM` | Start from IP number |
| `-l` | Loop mode (monitor changes) |
| `-b` | Randomize IP order |
| `-u` | Check for updates |
| `--clean-data` | Remove all generated data |
| `--uninstall` | Full cleanup |

## 🔒 Privacy & Safety

- **Dedicated Tor**: Scanner runs its OWN Tor instance (port 9060)
- **System Tor Untouched**: Your other apps (Simplex, browser) use port 9050 normally
- **No Conflicts**: ExitNodes settings only affect scanner's Tor
- **Auto Cleanup**: Scanner's Tor shuts down when script exits
- **All Local**: No external data collection

## 🗑️ Uninstall

```bash
python3 main.py --uninstall
rm -rf /path/to/ssavr-copypaste-scanner
```

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md)

---

**v6.0.0** | MIT License
