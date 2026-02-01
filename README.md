everything written here is completely done by AI, even the readme.

# 🌐 Tor Clipboard Scanner

**v5.6.0** - Anonymous clipboard monitoring through Tor exit nodes with parallel scanning

Scan ssavr.com and copy-paste.online through Tor exit nodes for maximum anonymity.

## ✨ Features

- **Parallel Scanning**: Both sites scanned simultaneously per IP
- **Real-Time UI**: Rich terminal dashboard with live status updates
- **IP Provider Rotation**: 5 fallback services for reliable IP verification
- **Graceful Shutdown**: Clean exit with statistics on Ctrl+C
- **Loop Mode**: Continuous monitoring with change detection

## 🚀 Quick Start

```bash
# Install dependencies
sudo apt install tor
pip install -r requirements.txt

# Setup Tor
tor --hash-password YOUR_PASSWORD
# Add to /etc/tor/torrc:
# ControlPort 9051
# HashedControlPassword 16:HASH_FROM_ABOVE
sudo systemctl restart tor

# Run
python3 main.py
```

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
python3 main.py -tsf s.txt -tcf c.txt   # From files

# Advanced
python3 main.py -w "Test" -o            # Overwrite own messages
python3 main.py -w "Test" -a            # Overwrite EVERYTHING (⚠️)
python3 main.py -i 100                  # Start from IP #100
python3 main.py -b                      # Randomize order
python3 main.py -t SS -w "Only SS"      # Target specific site
python3 main.py -u                      # Check for updates
```

## 📁 Files

### Main Directory
- `ssavr_clean.txt` - New content from ssavr.com (no duplicates)
- `copypaste_clean.txt` - New content from copy-paste.online (no duplicates)
- `changes.txt` - Changes detected in loop mode

### data/ Directory
- `ssavr_detailed.txt` - All ssavr.com reads
- `copypaste_detailed.txt` - All copy-paste.online reads
- `current_ssavr.txt` - Current state of all IPs (ssavr)
- `current_copypaste.txt` - Current state of all IPs (copypaste)
- `inputs_history.json` - Your message history
- `debug.log` - Debug information

## 🔧 Options

| Option | Description |
|--------|-------------|
| `-w TEXT` | Write to both sites |
| `-wf FILE` | Write from file to both sites |
| `-ts TEXT` | Write only to ssavr.com |
| `-tsf FILE` | Write from file to ssavr.com |
| `-tc TEXT` | Write only to copy-paste.online |
| `-tcf FILE` | Write from file to copy-paste.online |
| `-t SS/CP` | Target specific site |
| `-o` | Overwrite own messages |
| `-a` | Overwrite ANY content (⚠️) |
| `-s NUM` | Scan only one IP |
| `-i NUM` | Start from IP number |
| `-l` | Loop mode (monitor changes) |
| `-b` | Randomize IP order |
| `-k` | Show message history |
| `-u` | Check for updates |

## 💡 Tips

**Quotes**: Required when message contains spaces
```bash
✅ python3 main.py -w "Hello world"
✅ python3 main.py -w Hello
❌ python3 main.py -w Hello world
```

**From File**: Use `-wf`, `-tsf`, `-tcf` for longer messages
```bash
echo "Long message here" > msg.txt
python3 main.py -wf msg.txt
```

**Disable Advanced Features**: Create `data/.disable_advanced_features` (empty file)

## 🔒 Privacy

- Tor password stored locally (optional)
- Your messages tracked in history to identify later
- No third-party data collection
- All connections through Tor

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md)

## 🔗 Links

- **Repo**: https://github.com/Jester-tek/ssavr-copypaste-scanner
- **ssavr.com**: https://www.ssavr.com
- **copy-paste.online**: https://copy-paste.online

---

**v5.6.0** | MIT License
