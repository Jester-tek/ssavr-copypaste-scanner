everything written here is completely done by AI, even the readme.
# 🔐 Tor Clipboard Scanner

A Python tool to scan and interact with clipboard sharing websites ([ssavr.com](https://www.ssavr.com) and [copy-paste.online](https://copy-paste.online)) through different Tor exit nodes.

## 🎯 What does it do?

This tool allows you to:
- **Anonymously scan** clipboard websites from different IP addresses (Tor exit nodes)
- **Read messages** left by others on these public clipboards
- **Write messages** visible to someone who visits the site with the same Tor IP
- **Monitor changes** in real-time across all exit nodes
- **Track history** of your own messages to avoid logging them as "new"

## 🚀 Features

- ✅ Scans through hundreds of unique Tor exit nodes
- ✅ Reads and writes to ssavr.com and copy-paste.online
- ✅ Automatic CSRF token handling
- ✅ Smart message history tracking
- ✅ Loop mode for continuous monitoring
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
python3 tor_scanner.py
```

It will ask for your Tor control password. You can choose to save it to `.tor_scanner_config.json` for future runs.

**⚠️ Security Note:** The config file stores your password in plain text.

## 📖 Usage

### Basic Examples

#### Read-only scan (safest):
```bash
python3 tor_scanner.py
```
Scans all exit nodes and logs found messages without writing anything.

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
python3 tor_scanner.py -l
```
Continuously scans all exit nodes and logs any changes to `changes.txt`.

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

The script creates several log files:

| File | Description |
|------|-------------|
| `ssavr_detailed.txt` | All reads from ssavr.com (including empty and your own messages) |
| `ssavr_clean.txt` | Only NEW messages from others on ssavr.com |
| `copypaste_detailed.txt` | All reads from copy-paste.online (including empty and your own messages) |
| `copypaste_clean.txt` | Only NEW messages from others on copy-paste.online |
| `changes.txt` | Changes detected during loop mode |
| `inputs_history.json` | Your message history (used to identify your messages) |
| `.tor_scanner_config.json` | Saved Tor password (optional, created on first run) |

### Clean vs Detailed Logs

- **Detailed logs**: Contains every read attempt, including empty fields and your own messages
- **Clean logs**: Only contains genuinely new messages from others (filters out empty fields and your own messages)

## 🎮 Command Line Arguments

```
Required setup (first time):
  None - script will guide you through Tor password setup

Reading options:
  -i N, --index N       Start from exit node number N (default: 1)
  -b, --randomize       Randomize exit node order
  -l, --loop            Continuous monitoring mode

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
Your Tor control password is incorrect. Either:
- Delete `.tor_scanner_config.json` and re-enter the password
- Check your `/etc/tor/torrc` for the correct hashed password

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

