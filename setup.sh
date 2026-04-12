#!/bin/bash
# Tor Clipboard Scanner - Automated Multi-Distro Installer

echo "================================================"
echo "🚀 Installing Paste Scanner Dependencies"
echo "================================================"
echo ""

# Detect package manager
if command -v apt &> /dev/null; then
    echo "[1/3] Ubuntu/Debian detected. Installing Tor, Python, GCC..."
    sudo apt update
    sudo apt install -y tor python3-pip python3-venv gcc
elif command -v pacman &> /dev/null; then
    echo "[1/3] Arch Linux detected. Installing Tor, Python, GCC..."
    sudo pacman -Sy --noconfirm tor python-pip gcc
elif command -v dnf &> /dev/null; then
    echo "[1/3] Fedora detected. Installing Tor, Python, GCC..."
    sudo dnf install -y tor python3-pip gcc
elif command -v yum &> /dev/null; then
    echo "[1/3] RHEL/CentOS detected. Installing Tor, Python, GCC..."
    sudo yum install -y tor python3-pip gcc
else
    echo "⚠️  Unsupported package manager."
    echo "Please manually install: tor, python3-pip, gcc"
    echo "Then press Enter to continue with python setup..."
    read -r
fi

echo ""
echo "[2/3] Setting up isolated Python environment..."
# In some distros, venv is built-in; in Ubuntu it requires python3-venv
if [ ! -d "venv" ]; then
    python3 -m venv venv || { echo "⚠️ Failed to create venv. Make sure python3-venv is installed."; exit 1; }
fi
source venv/bin/activate

echo ""
echo "[3/3] Installing required Python libraries..."
pip install -r requirements.txt

echo ""
echo "================================================"
echo "✅ Installation Complete!"
echo "================================================"
echo ""
echo "To start the scanner, run these two commands:"
echo "  source venv/bin/activate"
echo "  python3 main.py"
echo ""
echo "Happy scanning! 🌐"
