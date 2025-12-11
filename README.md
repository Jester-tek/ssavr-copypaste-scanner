everything written here is completely done by AI, even the readme.
## 🆕 What's New in v3.0

### Critical Bug Fixes
- **🔴 Fixed session persistence bug** that was causing:
  - "23 user agents" ban on copy-paste.online
  - Phantom reads (seeing content from previous IPs)
  - Cookie contamination across different exit nodes
- **Fixed IP detection** with polling verification system
- **Fixed index bug** (-i now correctly 1-based)
- **Fixed text comparison** with clean_text() normalization

### New Features
- **Single IP mode** (`-s` flag) for testing specific exit nodes
- **Configurable Tor ports** for using Tor Browser
- **StrictNodes** enforcement for guaranteed IP consistency
- **IPv6 support** with robust validation
- **Debug logging** in `data/debug.log`

# 🔐 Tor Clipboard Scanner v3.0

A Python tool to scan and interact with clipboard sharing websites ([ssavr.com](https://www.ssavr.com) and [copy-paste.online](https://copy-paste.online)) through different Tor exit nodes.

## 🎯 What does it do?

This tool allows you to:
- **Anonymously scan** clipboard websites from different IP addresses (Tor exit nodes)
- **Read messages** left by others on these public clipboards
- **Write messages** that are only visible from certain geographic locations
- **Monitor changes** in real-time across all exit nodes
- **Track history** of your own messages to avoid logging them as "new"

## 🚀 Features

- ✅ Scans through hundreds of unique Tor exit nodes
- ✅ Reads and writes to ssavr.com and copy-paste.online
- ✅ Automatic CSRF token handling
- ✅ Smart message history tracking
- ✅ **Loop mode with persistent state** - survives restarts!
- ✅ **Auto-update system** - check for new versions with `-u`
- ✅ **Current state snapshots** - see what's on each IP right now
- ✅ **Change detection** - logs all modifications in loop mode
- ✅ **Organized file structure** - important files in root, details in `data/`
- ✅ **Fixed copy-paste.online rate limiting** - works reliably now!
- ✅ Detailed logging with separate files for clean results
- ✅ Statistics on failures and successes
- ✅ Randomization of IP order
- ✅ Selective targeting (one site or both)

## 📦 Installation

### 1. Install Dependencies

#### System packages (Debian/Ubuntu):
```bash
sudo apt update
sudo apt install tor python3 python3-pip
```

#### System packages (macOS):
```bash
brew install tor python3
```

#### Python packages:
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install requests[socks] stem beautifulsoup4
```

### 2. Configure Tor

#### Generate Tor Control Password:
```bash
tor --hash-password YOUR_PASSWORD
```

This will output something like: `16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C`

#### Edit Tor Configuration:
```bash
sudo nano /etc/tor/torrc
```

Add these lines (uncomment if they exist):
```
ControlPort 9051
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
```

Replace the hash with your generated hash from step 1.

#### Restart Tor:
```bash
sudo systemctl restart tor
# or on macOS:
brew services restart tor
```

### 3. First Run

Run the script for the first time:
```bash
python3 scanner.py
```

It will ask for your Tor control password. **Important:** Enter the **plain text password** you chose in step 1, **NOT** the hash that starts with `16:...`

You can choose to save it to `data/.tor_scanner_config.json` for future runs.

**⚠️ Security Note:** The config file stores your password in plain text. Keep it secure and don't commit it to version control!

### 4. Using Tor Browser (Alternative)

If you want to use Tor Browser instead of system Tor:

```bash
# Tor Browser uses different ports: 9150 (SOCKS) and 9151 (Control)
python3 scanner.py --socks-port 9150 --control-port 9151 [other options]

# Test with curl
curl --socks5-hostname 127.0.0.1:9150 https://ifconfig.co
```

**Note:** Tor Browser must be running and have Control Port enabled.

## 🔄 Updating

Check for updates anytime:
```bash
python3 scanner.py -u
```

The script will:
- Fetch the latest version from GitHub
- Show you what changed
- Preserve your configuration and log files
- Ask for confirmation before updating

## 🔧 Advanced Configuration

### Disable Text Normalization

To disable the text processing feature (no soft hyphen marker):

```bash
# Create empty file in data/ directory
touch data/.disable_advanced_features

# Verify it exists
ls -la data/.disable_advanced_features
```

This file is automatically preserved during updates and never committed to git.

### Debug Logging

When things don't work as expected, check `data/debug.log`:

```bash
tail -f data/debug.log
```

This log contains:
- Non-200 HTTP responses with headers
- Rate limit detections
- Exception details
- IP verification attempts

## 📖 Usage

### Basic Examples

#### Read-only scan (safest):
```bash
python3 scanner.py
```
Scans all exit nodes and logs found messages without writing anything.

#### Check for updates:
```bash
python3 scanner.py -u
```
Checks GitHub for new versions and updates while preserving your configuration.

#### Write to empty fields:
```bash
python3 tor_scanner.py -w "Hello from Tor!"
```
Writes your message only to empty clipboard fields.

#### Write to specific site:
```bash
python3 tor_scanner.py -t SS -w "Only visible on ssavr.com"
python3 tor_scanner.py -t CP -w "Only visible on copy-paste.online"
```

#### Different messages per site:
```bash
python3 tor_scanner.py -ts "Message for ssavr" -tc "Message for copy-paste"
```

#### Overwrite your own messages:
```bash
python3 tor_scanner.py -w "New message" -o
```
Updates your previous messages. Uses history to identify which messages are yours.

#### Overwrite everything (dangerous!):
```bash
python3 tor_scanner.py -w "Override all" -a
```
⚠️ **Warning:** Overwrites ANY content found, not just yours!

#### Monitor mode:
```bash
python3 scanner.py -l
```
Continuously scans all exit nodes and logs any changes to `changes.txt`.

**Features:**
- Persists state across restarts - you can stop and resume days later!
- Automatically detects new/removed exit nodes
- Only logs actual changes (not initial scan)
- State saved in `current_state.json`

#### Start from specific IP:
```bash
python3 tor_scanner.py -i 500
```
Starts scanning from exit node #500 instead of #1.

#### Randomize IP order:
```bash
python3 tor_scanner.py -w "Test" -b
```
Scans exit nodes in random order instead of sequential.

### History Management

The script tracks messages you've written in `inputs_history.json` to avoid logging them as "new content".

#### Show history:
```bash
python3 tor_scanner.py -k
```

#### Add message to history manually:
```bash
python3 tor_scanner.py -x "Old message I wrote before"
```
Useful if you wrote messages manually and want the scanner to recognize them as yours.

#### Remove from history:
```bash
python3 tor_scanner.py -r "Message to remove"
```

## 📁 Output Files

The script creates log files organized in two locations:

### Main Directory (Frequently Accessed)
| File | Description |
|------|-------------|
| `ssavr_clean.txt` | Only NEW messages from others on ssavr.com |
| `copypaste_clean.txt` | Only NEW messages from others on copy-paste.online |
| `changes.txt` | Changes detected during loop mode (persistent across restarts) |

### data/ Directory (Detailed Logs & Config)
| File | Description |
|------|-------------|
| `ssavr_detailed.txt` | All reads from ssavr.com (including empty and your own messages) |
| `copypaste_detailed.txt` | All reads from copy-paste.online (including empty and your own messages) |
| `current_ssavr.txt` | **Current state snapshot** - latest content on all IPs for ssavr.com |
| `current_copypaste.txt` | **Current state snapshot** - latest content on all IPs for copy-paste.online |
| `inputs_history.json` | Your message history (used to identify your messages) |
| `current_state.json` | Internal state for loop mode (persistent across restarts) |
| `.tor_scanner_config.json` | Saved Tor password (optional, created on first run) |
| `.disable_advanced_features` | Optional file to disable text processing features |

### File Organization Philosophy

**v2.0 reorganized files for better usability:**
- **Main directory**: Files you check frequently (clean logs, changes)
- **data/ directory**: Everything else (detailed logs, config, state files)
- This keeps your main directory clean while preserving all functionality

### Clean vs Detailed Logs

- **Detailed logs**: Contains every read attempt, including empty fields and your own messages
- **Clean logs**: Only contains genuinely new messages from others (filters out empty fields and your own messages)

### Current State Files

`current_ssavr.txt` and `current_copypaste.txt` provide a real-time snapshot of what's currently visible on each IP address:

```
# Current state of ssavr.com
# Last updated: 2024-12-10 16:45:23
# Total IPs tracked: 150
================================================================================

[IP: 45.67.89.123]
  Last updated: 2024-12-10 16:45:23
  Content: Hello from Italy
--------------------------------------------------------------------------------

[IP: 98.76.54.321]
  Last updated: 2024-12-10 16:45:30
  Content: (empty)
--------------------------------------------------------------------------------
```

These files:
- Update on every scan (any mode)
- Track each unique IP address
- Show timestamps and current content
- Handle IP changes gracefully (as exit nodes come/go)

### Loop Mode & Changes

In loop mode (`-l`):
1. **First run**: Creates `changes.txt`, scans all IPs, saves state
2. **Subsequent runs**: Compares with previous state, logs only CHANGES
3. **After restart**: Loads previous state from `data/current_state.json`, continues monitoring
4. **New IPs**: Automatically detected, no false "changes" logged

## 🎮 Command Line Arguments

```
Advanced:
  --socks-port N        Tor SOCKS port (default: 9050, Tor Browser: 9150)
  --control-port N      Tor Control port (default: 9051, Tor Browser: 9151)

Update system:
  -u, --update          Check for script updates from GitHub

Reading options:
  -i N, --index N       Start from IP number N (1-based, e.g., -i 100 = IP #100)
  -s N, --single N      Scan ONLY IP number N and stop (1-based, e.g., -s 139)
  -b, --randomize       Randomize exit node order
  -l, --loop            Continuous monitoring mode (persists across restarts)

Writing options:
  -w MSG, --write       Write message to both sites (only to empty fields)
  -t {SS,CP}            Target: SS (ssavr.com) or CP (copy-paste.online)
  -ts MSG               Write message only to ssavr.com
  -tc MSG               Write message only to copy-paste.online
  -o, --overwrite       Also overwrite your own previous messages
  -a, --all             Overwrite ANY content (⚠️ dangerous!)

History management:
  -k, --show-history    Show message history
  -x MSG                Add message to history
  -r MSG                Remove message from history

Help:
  -h, --help            Show help message
```

## 🔒 Privacy & Ethics

### What this tool does:
- ✅ Scans **public** clipboard websites that anyone can access
- ✅ Uses Tor for **anonymity**
- ✅ Respects rate limits with delays between requests

### What you should NOT do:
- ❌ Use `-a` flag carelessly (overwrites everyone's content)
- ❌ Spam or abuse the services
- ❌ Post illegal or harmful content
- ❌ Use for harassment or malicious purposes

**Remember:** These are public services. Be respectful of other users.

## 🛠️ Troubleshooting

### "Cannot connect to Tor Control Port"
1. Make sure Tor is running: `sudo systemctl status tor`
2. Check that ControlPort is enabled in `/etc/tor/torrc`
3. Verify your password is correct

### "Authentication failed"
Your Tor control password is incorrect. **Make sure you're entering the plain text password, NOT the hash!**

Common mistake:
- ❌ Wrong: Entering `16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C`
- ✅ Correct: Entering `mypassword123` (the password you used in `tor --hash-password`)

To fix:
- Delete `.tor_scanner_config.json` and re-enter the **plain text password**
- Check your `/etc/tor/torrc` has the correct HashedControlPassword

### "Read failed" / "Write failed"
- Network issues or Tor circuit problems
- Try running again - Tor will use different circuits
- Check the site is accessible: `curl -x socks5h://127.0.0.1:9050 https://www.ssavr.com`

### Script is very slow
- This is normal! Each exit node requires:
  - Changing circuit (3 seconds)
  - HTTP requests (1-5 seconds each)
  - Multiple requests per site (read, write, verify)
- 100 exit nodes = ~15-30 minutes

### "Too many failed requests"
- Some exit nodes may be blocked by the websites
- This is normal and expected
- The statistics at the end show how many succeeded vs failed

## 📊 Statistics

Press `Ctrl+C` at any time to see statistics:
```
📊 STATISTICS
═══════════════
[ssavr.com]
  ❌ Read failures: 5
  ❌ Write failures: 2
  ❌ Verify failures: 1

[copy-paste.online]
  ❌ Read failures: 3
  ❌ Write failures: 1
  ❌ Verify failures: 0

🔴 Total failures: 12
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Ideas for contributions:
- Add support for more clipboard websites
- Implement automatic retry on failed requests
- Add geographic filtering of exit nodes
- Create a GUI version
- Add export functionality (CSV, JSON)

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this program. Always respect the terms of service of the websites you interact with and local laws regarding automated access to web services.

## 🙏 Acknowledgments

- [Tor Project](https://www.torproject.org/) for the anonymity network
- [stem](https://stem.torproject.org/) for Tor controller library
- [ssavr.com](https://www.ssavr.com) and [copy-paste.online](https://copy-paste.online) for their public clipboard services

---

**Made with ❤️ for the privacy community**
